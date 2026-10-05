use discortp::rtp::RtpPacket;

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
/// Opus audio packet, received from another stream
///
/// `payload_offset` and `payload_end_pad` bound the true payload within the raw packet's
/// `payload()`, if extensions or raw packet data are required: the Opus frame is
/// `payload()[payload_offset..payload().len() - payload_end_pad]`.
pub struct RtpData {
    /// Raw RTP packet data.
    ///
    /// Includes the SSRC (i.e., sender) of this packet.
    pub packet: Bytes,
    /// Byte index into the packet body (after headers) for where the payload begins.
    ///
    /// For a decrypted packet this is past any header extension.
    pub payload_offset: usize,
    /// Number of bytes at the end of the packet body to discard.
    ///
    /// For a decrypted packet these are the transport tag and nonce, any RTP
    /// padding, and any DAVE trailer left behind by end-to-end decryption.
    pub payload_end_pad: usize,
}

impl RtpData {
    /// Create a zero-copy view of the inner RTP packet.
    ///
    /// This allows easy access to packet header fields, taking them from the underlying
    /// `Bytes` as needed while handling endianness etc.
    pub fn rtp(&'_ self) -> RtpPacket<'_> {
        RtpPacket::new(&self.packet)
            .expect("FATAL: leaked illegally small RTP packet from UDP Rx task.")
    }
}
