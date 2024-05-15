use anyhow::anyhow;
use anyhow::Ok;
use mp3lame_encoder::Builder;
use mp3lame_encoder::FlushNoGap;
use mp3lame_encoder::InterleavedPcm;

use super::Samples;
use super::Encoder;
use super::EncodedStream;

pub struct Mp3Encoder;

impl Mp3Encoder {
    fn build_encoder(&self, sample_rate: u32, channels: u32) -> anyhow::Result<mp3lame_encoder::Encoder> {
        let mut builder = Builder::new().
            ok_or(anyhow::anyhow!("Failed to create mp3 encoder"))?;
        
        builder.set_sample_rate(sample_rate)
            .map_err(|e| anyhow::anyhow!("Failed to set sample rate for mp3 encoder: {}", e))?;
        builder.set_num_channels(channels as u8)
            .map_err(|e| anyhow::anyhow!("Failed to set number of channels for mp3 encoder: {}", e))?;
        builder.set_brate(mp3lame_encoder::Birtate::Kbps160)
            .map_err(|e| anyhow::anyhow!("Failed to set bitrate for mp3 encoder: {}", e))?;
        
        builder.build()
            .map_err(|e| anyhow::anyhow!("Failed to build mp3 encoder: {}", e))
    }
}

impl Encoder for Mp3Encoder {
    fn encode(&self, samples: Samples) -> anyhow::Result<EncodedStream> {
        let mut mp3_encoder = self.build_encoder(samples.sample_rate, samples.channels)?;

        let samples: Vec<i16> = samples.samples.iter().map(|&x| x as i16).collect();
        let input = InterleavedPcm(samples.as_slice());
        let mut mp3_out_buffer = Vec::new();
        mp3_out_buffer.reserve(mp3lame_encoder::max_required_buffer_size(samples.len()));
        let encoded_size = mp3_encoder.encode(input, mp3_out_buffer.spare_capacity_mut())
            .map_err(|e| anyhow!("Failed to encode mp3: {}", e))?;
        unsafe {
            mp3_out_buffer.set_len(mp3_out_buffer.len().wrapping_add(encoded_size));
        }

        let encoded_size = mp3_encoder.flush::<FlushNoGap>(mp3_out_buffer.spare_capacity_mut())
            .map_err(|e| anyhow!("Failed to flush mp3 encoder: {}", e))?;
        unsafe {
            mp3_out_buffer.set_len(mp3_out_buffer.len().wrapping_add(encoded_size));
        }
        
        Ok(EncodedStream::new(mp3_out_buffer))
    }
}