use crate::{
    poseidon2::{poseidon2_compress, Poseidon2BabyBearShort},
    poseidon2_config::{poseidon2_instance, poseidon2_instance_short},
    tweak::{PoseidonTweak, TweakTransfformation},
};
use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_field::FieldAlgebra;

const DOMAIN_PARAMETERS_LENGTH: usize = 4;

/// A Poseidon tweak hash representation.
///
/// This struct defines a tweakable hash function based on the Poseidon2 permutation.
///
/// ## Parameters:
///
/// - `LOG_LIFETIME`: Determines the total lifetime of the Merkle tree in powers of 2. The number of
///   leaves in the Merkle tree for this instantiation is `2^LOG_LIFETIME`. A higher value means a
///   longer lifetime, allowing more signatures before key rotation is needed.
///
/// - `CEIL_LOG_NUM_CHAINS`: Represents an upper bound (ceil) on the logarithm (base 2) of the
///   number of chains in the hash-based signature scheme. This affects the number of parallel
///   chains used in signature generation, ensuring security and efficiency.
///
/// - `CHUNK_SIZE`: Defines the number of field elements per chunk when processing messages. Larger
///   chunk sizes reduce the number of hash function calls but require more precomputed values.
///
/// - `PARAMETER_LEN`: Specifies the number of field elements used to encode public parameters.
///   Public parameters are fixed per user or system-wide and are included in the hashing process.
///
/// - `HASH_LEN`: The length of the hash output in terms of field elements. This defines the
///   security level of the hash function, affecting collision and preimage resistance.
///
/// - `TWEAK_LEN`: Defines the number of field elements used to encode the tweak. The tweak provides
///   domain separation between different hash function calls, preventing collision attacks and
///   ensuring security in hierarchical signature schemes.
///
/// - `CAPACITY`: Represents the number of field elements reserved for capacity in the Poseidon
///   sponge. Capacity determines resistance to collision attacks by ensuring enough diffusion in
///   the permutation.
///
/// - `NUM_CHUNKS`: Defines the total number of chunks used to process an input message. This
///   determines how the message is split for hashing and affects the overall signature scheme
///   efficiency.
#[derive(Debug, Clone)]
pub struct PoseidonTweakHash<
    const LOG_LIFETIME: usize,
    const CEIL_LOG_NUM_CHAINS: usize,
    const CHUNK_SIZE: usize,
    const PARAMETER_LEN: usize,
    const HASH_LEN: usize,
    const TWEAK_LEN: usize,
    const CAPACITY: usize,
    const NUM_CHUNKS: usize,
> {
    parameter: [BabyBear; PARAMETER_LEN],
    tweak: PoseidonTweak,
    message: Vec<[BabyBear; HASH_LEN]>,
}

impl<
        const LOG_LIFETIME: usize,
        const CEIL_LOG_NUM_CHAINS: usize,
        const CHUNK_SIZE: usize,
        const PARAMETER_LEN: usize,
        const HASH_LEN: usize,
        const TWEAK_LEN: usize,
        const CAPACITY: usize,
        const NUM_CHUNKS: usize,
    >
    PoseidonTweakHash<
        LOG_LIFETIME,
        CEIL_LOG_NUM_CHAINS,
        CHUNK_SIZE,
        PARAMETER_LEN,
        HASH_LEN,
        TWEAK_LEN,
        CAPACITY,
        NUM_CHUNKS,
    >
{
    pub fn apply(&self) -> [BabyBear; HASH_LEN] {
        match self.message.len() {
            1 => {
                // we compress parameter, tweak, message
                let tweak_fe: [_; TWEAK_LEN] = self.tweak.to_field_elements();
                let combined_input: Vec<BabyBear> = self
                    .parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(self.message[0].iter())
                    .cloned()
                    .collect();
                poseidon2_compress::<HASH_LEN, _>(&poseidon2_instance_short(), &combined_input)
            }
            2 => {
                let tweak_fe: [_; TWEAK_LEN] = self.tweak.to_field_elements();

                let combined_input: Vec<BabyBear> = self
                    .parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(self.message[0].iter())
                    .chain(self.message[1].iter())
                    .cloned()
                    .collect();

                poseidon2_compress::<HASH_LEN, _>(&poseidon2_instance(), &combined_input)
            }
            _ => {
                let tweak_fe: [_; TWEAK_LEN] = self.tweak.to_field_elements();

                let combined_input: Vec<BabyBear> = self
                    .parameter
                    .iter()
                    .chain(tweak_fe.iter())
                    .chain(self.message.iter().flat_map(|sub_arr| sub_arr.iter()))
                    .cloned()
                    .collect();

                let lengths: [usize; DOMAIN_PARAMETERS_LENGTH] =
                    [PARAMETER_LEN, TWEAK_LEN, NUM_CHUNKS, HASH_LEN];

                let poseidon_instance = poseidon2_instance();

                // let safe_input =
                //     poseidon_safe_domain_separator::<CAPACITY>(&poseidon_instance, &lengths);
                // poseidon_sponge(&poseidon_instance, &safe_input, &combined_input)

                [BabyBear::ZERO; HASH_LEN]
            }
        }
    }
}
