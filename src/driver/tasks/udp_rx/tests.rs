use super::*;
use crate::{
    driver::{crypto::CryptoState, Channels, DecodeConfig, SampleRate},
    events::context_data::RtpData,
};
use bytes::Bytes;
use discortp::rtp::MutableRtpPacket;
use opus2::{
    Application,
    Channels as OpusChannels,
    Decoder as OpusDecoder,
    Encoder as OpusEncoder,
};
use std::{f32::consts::TAU, num::NonZeroU8};

const SSRC: u32 = 0x5EED;

/// Decode into `decode`, releasing every stored packet on the next tick.
fn rx_config(decode: DecodeConfig) -> Config {
    Config::default()
        .decode_mode(DecodeMode::Decode(decode))
        .playout_buffer_length(NonZeroU8::new(1).unwrap())
}

/// One 20ms Opus frame of a two-tone signal, encoded at 48kHz mono in audio mode.
///
/// CELT reads raw bits from the end of a frame, so bytes appended to this frame
/// change what decodes from it: the tests below rely on that (and check it).
fn opus_frame() -> Vec<u8> {
    let mut encoder = OpusEncoder::new(48_000, OpusChannels::Mono, Application::Audio).unwrap();
    let pcm: Vec<i16> = (0..MONO_FRAME_SIZE)
        .map(|i| {
            let t = i as f32 / 48_000.0;
            ((t * 440.0 * TAU).sin() * 8000.0 + (t * 3100.0 * TAU).sin() * 4000.0) as i16
        })
        .collect();
    let mut out = vec![0u8; 1275];
    let len = encoder.encode(&pcm, &mut out).unwrap();
    out.truncate(len);
    out
}

/// What a fresh decoder makes of exactly `data`, or `None` if it refuses it.
fn fresh_decode(data: &[u8], decode: DecodeConfig) -> Option<Vec<i16>> {
    let mut decoder = OpusDecoder::new(decode.sample_rate.into(), decode.channels.into()).unwrap();
    let mut out = vec![0; 6 * STEREO_FRAME_SIZE];
    let len = decoder.decode(data, &mut out, false).ok()?;
    out.truncate(len * decode.channels.channels());
    Some(out)
}

/// A cleartext RTP packet from `SSRC` carrying `payload`.
fn rtp_packet(seq: u16, timestamp: u32, padding: bool, payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; MutableRtpPacket::minimum_packet_size() + payload.len()];
    let mut rtp = MutableRtpPacket::new(&mut buf).unwrap();
    rtp.set_version(RTP_VERSION);
    rtp.set_padding(u8::from(padding));
    rtp.set_payload_type(RTP_PROFILE_TYPE);
    rtp.set_sequence(seq.into());
    rtp.set_timestamp(timestamp.into());
    rtp.set_ssrc(SSRC);
    rtp.payload_mut().copy_from_slice(payload);
    buf
}

/// The bytes `data` marks as its Opus frame.
fn marked_frame(data: &RtpData) -> Vec<u8> {
    let rtp = data.rtp();
    let payload = rtp.payload();
    payload[data.payload_offset..payload.len() - data.payload_end_pad].to_vec()
}

#[test]
fn dave_trailer_never_reaches_decoder() {
    let decode = DecodeConfig::new(Channels::Mono, SampleRate::Hz48000);
    let config = rx_config(decode);
    let frame = opus_frame();

    // In-place DAVE decryption writes the plaintext frame over the front of the
    // DAVE frame and leaves the rest of its trailer behind it: the 8-byte
    // truncated tag, the ULEB128 nonce, the supplemental size byte, and 0xFAFA.
    let mut dave_leftover = vec![0xA5; 8];
    dave_leftover.extend_from_slice(&[0x2A, 11]);
    dave_leftover.extend_from_slice(&DAVE_MAGIC_MARKER);
    let transport_suffix = CryptoMode::Aes256Gcm.payload_suffix_len();

    let mut with_trailer = frame.clone();
    with_trailer.extend_from_slice(&dave_leftover);
    assert_ne!(
        fresh_decode(&with_trailer, decode),
        fresh_decode(&frame, decode),
        "the trailer must change the decode, or this test cannot see it"
    );

    let mut payload = with_trailer;
    payload.extend(std::iter::repeat_n(0x77, transport_suffix));
    let packet = rtp_packet(1, 0, false, &payload);

    let mut state = SsrcState::new(&RtpPacket::new(&packet).unwrap(), &config);
    state.store_packet(
        StoredPacket {
            packet: Bytes::from(packet),
            decrypted: true,
            payload_offset: 0,
            payload_end_pad: dave_leftover.len() + transport_suffix,
        },
        &config,
    );

    let tick = state
        .get_voice_tick(&config)
        .unwrap()
        .expect("one packet is due");
    assert_eq!(tick.decoded_voice, fresh_decode(&frame, decode));
    assert_eq!(marked_frame(&tick.packet.unwrap()), frame);
}

#[tokio::test]
async fn rtp_padding_never_reaches_decoder() {
    let decode = DecodeConfig::new(Channels::Mono, SampleRate::Hz16000);
    let config = rx_config(decode);
    let mode = CryptoMode::Aes256Gcm;
    let key = [7u8; 32];
    let frame = opus_frame();

    // RFC 3550: the last padding octet counts the padding, itself included.
    let mut plaintext = frame.clone();
    plaintext.extend_from_slice(&[0, 0, 0, 4]);
    assert_ne!(
        fresh_decode(&plaintext, decode),
        fresh_decode(&frame, decode),
        "the padding must change the decode, or this test cannot see it"
    );

    let mut buf = rtp_packet(
        1,
        0,
        true,
        &vec![0; plaintext.len() + mode.payload_suffix_len()],
    );
    let mut rtp = MutableRtpPacket::new(&mut buf).unwrap();
    rtp.payload_mut()[..plaintext.len()].copy_from_slice(&plaintext);
    let payload_len = CryptoState::from(mode).write_packet_nonce(&mut rtp, plaintext.len());
    let cipher = mode.cipher_from_key(&key).unwrap();
    cipher.encrypt_pkt_in_place(&mut rtp, payload_len).unwrap();

    let (events, events_rx) = flume::unbounded();
    let (core, _core_rx) = flume::unbounded();
    let (mixer, _mixer_rx) = flume::unbounded();
    let interconnect = Interconnect {
        core,
        events,
        mixer,
    };
    let (_udp_tx, udp_rx_messages) = flume::unbounded();
    let mut udp_rx = UdpRx {
        cipher,
        crypto_mode: mode,
        decoder_map: HashMap::new(),
        config: config.clone(),
        rx: udp_rx_messages,
        ssrc_signalling: Arc::default(),
        udp_socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        dave_session: Arc::new(RwLock::new(None)),
        dave_protocol_version: Arc::new(AtomicU16::new(0)),
    };

    udp_rx
        .process_udp_message(&interconnect, BytesMut::from(&buf[..]))
        .await;

    let Ok(EventMessage::FireCoreEvent(CoreContext::RtpPacket(event))) = events_rx.try_recv()
    else {
        panic!("the packet should have been announced");
    };

    let tick = udp_rx
        .decoder_map
        .get_mut(&SSRC)
        .expect("the packet should have been stored")
        .get_voice_tick(&config)
        .unwrap()
        .expect("one packet is due");
    assert_eq!(tick.decoded_voice, fresh_decode(&frame, decode));

    // Both events describe the frame with the same bounds, the end as a count.
    let data = tick.packet.unwrap();
    assert_eq!(marked_frame(&data), frame);
    assert_eq!(
        (event.payload_offset, event.payload_end_pad),
        (data.payload_offset, data.payload_end_pad)
    );
}

#[test]
fn padding_count_is_checked() {
    let tag = CryptoMode::Aes256Gcm.payload_suffix_len();
    let payload = |body: &[u8]| {
        let mut payload = body.to_vec();
        payload.extend(std::iter::repeat_n(0, tag));
        payload
    };

    // Opus frame [1, 2, 3], then two padding octets.
    assert_eq!(
        opus_frame_bounds(&payload(&[1, 2, 3, 0, 2]), 0, tag, true),
        Some((0, tag + 2))
    );
    // Without the padding bit, the last byte is frame.
    assert_eq!(
        opus_frame_bounds(&payload(&[1, 2, 3, 0, 2]), 0, tag, false),
        Some((0, tag))
    );
    // A count larger than the body, or one that eats into a header extension.
    assert_eq!(opus_frame_bounds(&payload(&[1, 2, 9]), 0, tag, true), None);
    assert_eq!(opus_frame_bounds(&payload(&[1, 2, 2]), 2, tag, true), None);
    // A zero count cannot include itself.
    assert_eq!(opus_frame_bounds(&payload(&[1, 2, 0]), 0, tag, true), None);
    // An extension reaching into the cipher suffix, and a payload shorter than it.
    assert_eq!(opus_frame_bounds(&payload(&[1, 2]), 3, tag, false), None);
    assert_eq!(opus_frame_bounds(&[0; 4], 0, tag, false), None);
}
