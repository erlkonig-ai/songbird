use super::*;
use crate::{
    driver::{
        tasks::error::{Error, Result},
        Channels,
        DecodeConfig,
        DecodeMode,
        SampleRate,
    },
    events::context_data::{RtpData, VoiceData},
};
use discortp::Packet;
use opus2::{Decoder as OpusDecoder, ErrorCode};
use tracing::{error, warn};

#[derive(Debug)]
pub struct SsrcState {
    playout_buffer: PlayoutBuffer,
    decoder: OpusDecoder,
    decode_size: PacketDecodeSize,
    pub(crate) prune_time: Instant,
    pub(crate) disconnected: bool,
    channels: Channels,
    sample_rate: SampleRate,
}

impl SsrcState {
    pub fn new(pkt: &RtpPacket<'_>, config: &Config) -> Self {
        let playout_capacity = config.playout_buffer_length.get() + config.playout_spike_length;
        let (sample_rate, channels) = match config.decode_mode {
            DecodeMode::Decode(config) => (config.sample_rate, config.channels),
            DecodeMode::Decrypt | DecodeMode::Pass => Default::default(),
        };

        Self {
            playout_buffer: PlayoutBuffer::new(usize::from(playout_capacity), pkt.get_sequence().0),
            decoder: OpusDecoder::new(sample_rate.into(), channels.into())
                .expect("Failed to create new Opus decoder for source."),
            decode_size: PacketDecodeSize::TwentyMillis,
            prune_time: Instant::now() + config.decode_state_timeout.into(),
            disconnected: false,
            channels,
            sample_rate,
        }
    }

    pub fn reconfigure_decoder(&mut self, config: DecodeConfig) {
        self.decoder = OpusDecoder::new(config.sample_rate.into(), config.channels.into())
            .expect("Failed to create new Opus decoder for source.");

        self.channels = config.channels;
        self.sample_rate = config.sample_rate;
    }

    /// Number of samples (all channels) in one tick's worth of output audio.
    ///
    /// Loss concealment produces exactly as many samples as it is asked for, so
    /// the request must be sized from the output format rather than from the
    /// 48kHz stereo frame size.
    fn tick_len(&self) -> usize {
        let per_channel = u32::from(self.sample_rate) as usize / AUDIO_FRAME_RATE;
        per_channel * self.channels.channels()
    }

    pub fn store_packet(&mut self, packet: StoredPacket, config: &Config) {
        self.playout_buffer.store_packet(packet, config);
    }

    pub fn refresh_timer(&mut self, state_timeout: Duration) {
        if !self.disconnected {
            self.prune_time = Instant::now() + state_timeout;
        }
    }

    pub fn get_voice_tick(&mut self, config: &Config) -> Result<Option<VoiceData>> {
        // Acquire a packet from the playout buffer:
        // Update nexts, lasts...
        // different cases: null packet who we want to decode as a miss, and packet who we must ignore temporarily.
        let m_pkt = self.playout_buffer.fetch_packet(config);
        let pkt = match m_pkt {
            PacketLookup::Packet(pkt) => Some(pkt),
            PacketLookup::MissedPacket => None,
            PacketLookup::Filling => return Ok(None),
        };

        let mut out = VoiceData {
            packet: None,
            decoded_voice: None,
        };

        let should_decode = config.decode_mode.should_decode();
        if let Some(StoredPacket {
            packet,
            decrypted,
            payload_offset,
            payload_end_pad,
        }) = pkt
        {
            let rtp = RtpPacket::new(&packet).unwrap();

            // The receive path located the Opus frame when it decrypted the packet
            // (header extension, RTP padding, and any DAVE trailer all excluded).
            // Only that frame may reach the decoder.
            let payload = rtp.payload();
            let frame = payload
                .len()
                .checked_sub(payload_end_pad)
                .and_then(|end| payload.get(payload_offset..end))
                .ok_or(Error::IllegalVoicePacket)?;

            // We still need to compute missed packets here in case of long loss chains or similar.
            // This occurs due to the fallback in 'store_packet' (i.e., empty buffer and massive seq difference).
            // Normal losses should be handled by the below `else` branch.
            let new_seq: u16 = rtp.get_sequence().into();
            let missed_packets = new_seq.saturating_sub(self.playout_buffer.next_seq().0);

            let audio = self.scan_and_decode(frame, missed_packets, should_decode && decrypted)?;

            let rtp_data = RtpData {
                packet,
                payload_offset,
                payload_end_pad,
            };

            out.packet = Some(rtp_data);
            out.decoded_voice = audio;
        } else if should_decode {
            let mut audio = vec![0; self.tick_len()];
            let dest_samples = (&mut audio[..])
                .try_into()
                .expect("Decode logic will cap decode buffer size at i32::MAX.");
            let len = self.decoder.decode(&[], dest_samples, false)?;
            audio.truncate(self.channels.channels() * len);

            out.decoded_voice = Some(audio);
        }

        Ok(Some(out))
    }

    /// Decodes one Opus frame, concealing `missed_packets` lost frames before it.
    fn scan_and_decode(
        &mut self,
        frame: &[u8],
        missed_packets: u16,
        decode: bool,
    ) -> Result<Option<Vec<i16>>> {
        let pkt = if decode {
            let mut concealed = vec![0; self.tick_len()];
            for _ in 0..missed_packets {
                if let Err(e) = self.decoder.decode(&[], &mut concealed, false) {
                    warn!("Issue while decoding for missed packet: {:?}.", e);
                }
            }

            let mut out = vec![0; self.decode_size.len()];

            // In general, we should expect 20 ms frames.
            // However, Discord occasionally like to surprise us with something bigger.
            // This is *sender-dependent behaviour*.
            //
            // This should scan up to find the "correct" size that a source is using,
            // and then remember that.
            loop {
                let tried_audio_len = self.decoder.decode(frame, &mut out, false);
                match tried_audio_len {
                    Ok(audio_len) => {
                        // Decoding to stereo: audio_len refers to sample count irrespective of channel count.
                        // => multiply by number of channels.
                        out.truncate(self.channels.channels() * audio_len);

                        break;
                    },
                    Err(e) if e.code() == ErrorCode::BufferTooSmall => {
                        if self.decode_size.can_bump_up() {
                            self.decode_size = self.decode_size.bump_up();
                            out = vec![0; self.decode_size.len()];
                        } else {
                            error!("Received packet larger than Opus standard maximum,");
                            return Err(Error::IllegalVoicePacket);
                        }
                    },
                    Err(e) => {
                        error!("Failed to decode received packet: {:?}.", e);
                        return Err(e.into());
                    },
                }
            }

            Some(out)
        } else {
            None
        };

        Ok(pkt)
    }
}
