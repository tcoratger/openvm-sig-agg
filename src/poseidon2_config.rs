use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_field::{Field, FieldAlgebra};
use p3_poseidon2::ExternalLayerConstants;
use std::sync::OnceLock;
use zkhash::{
    ark_ff::PrimeField,
    fields::babybear::FpBabyBear as HorizenBabyBear,
    poseidon2::poseidon2_instance_babybear::{RC16, RC24},
};

/// The half of the Baby Bear Poseidon2 full round permutation
pub const BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS: usize = 4;
/// The number of full rounds of the Baby Bear Poseidon2 permutation
pub const BABY_BEAR_POSEIDON2_FULL_ROUNDS: usize = 8;
/// The number of partial rounds of the Baby Bear Poseidon2 permutation (16 state width version)
pub const BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_16: usize = 13;
/// The number of partial rounds of the Baby Bear Poseidon2 permutation (24 state width version)
pub const BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_24: usize = 21;

/// The degree of the Baby Bear Poseidon2 SBox component
pub const BABY_BEAR_POSEIDON2_SBOX_DEGREE: u64 = 7;

/// The width of the Baby Bear Poseidon2 permutation (16 state width version)
pub const POSEIDON2_WIDTH_16: usize = 16;

/// The width of the Baby Bear Poseidon2 permutation (24 state width version)
pub const POSEIDON2_WIDTH_24: usize = 24;

pub(crate) fn horizen_to_p3_babybear(horizen_babybear: &HorizenBabyBear) -> BabyBear {
    BabyBear::from_canonical_u64(horizen_babybear.into_bigint().0[0])
}

/// Generates Poseidon2 round constants for a given `WIDTH`
fn generate_round_constants<const WIDTH: usize, const P: usize>(
    rc_source: &[Vec<HorizenBabyBear>],
) -> Poseidon2Constants<WIDTH, P, BabyBear> {
    let p3_rc: Vec<Vec<_>> =
        rc_source.iter().map(|round| round.iter().map(horizen_to_p3_babybear).collect()).collect();

    let p_end = match WIDTH {
        16 => BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS + BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_16,
        24 => BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS + BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_24,
        _ => unreachable!(),
    };

    Poseidon2Constants {
        beginning_full_round_constants: core::array::from_fn(|i| {
            p3_rc[i].clone().try_into().unwrap()
        }),
        partial_round_constants: core::array::from_fn(|i| {
            p3_rc[i + BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS][0]
        }),
        ending_full_round_constants: core::array::from_fn(|i| {
            p3_rc[i + p_end].clone().try_into().unwrap()
        }),
    }
}

/// Struct containing Poseidon2 round constants
#[derive(Clone, Copy, Debug)]
pub struct Poseidon2Constants<const WIDTH: usize, const P: usize, F> {
    pub beginning_full_round_constants: [[F; WIDTH]; BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS],
    pub partial_round_constants: [F; P],
    pub ending_full_round_constants: [[F; WIDTH]; BABY_BEAR_POSEIDON2_HALF_FULL_ROUNDS],
}

impl<const WIDTH: usize, const P: usize, F: Field> Poseidon2Constants<WIDTH, P, F> {
    pub fn to_external_internal_constants(&self) -> (ExternalLayerConstants<F, WIDTH>, Vec<F>) {
        (
            ExternalLayerConstants::new(
                self.beginning_full_round_constants.to_vec(),
                self.ending_full_round_constants.to_vec(),
            ),
            self.partial_round_constants.to_vec(),
        )
    }
}

pub fn poseidon2_instance_short() -> Poseidon2BabyBear<16> {
    let poseidon_constants =
        generate_round_constants::<16, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_16>(&RC16);
    let (external_constants, internal_constants) =
        poseidon_constants.to_external_internal_constants();
    Poseidon2BabyBear::new(external_constants, internal_constants)
}

pub fn poseidon2_instance() -> Poseidon2BabyBear<24> {
    let poseidon_constants =
        generate_round_constants::<24, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_24>(&RC24);
    let (external_constants, internal_constants) =
        poseidon_constants.to_external_internal_constants();
    Poseidon2BabyBear::new(external_constants, internal_constants)
}

/// Lazy-loaded constants for `WIDTH = 16`
static BABYBEAR_POSEIDON2_16: OnceLock<
    Poseidon2Constants<16, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_16, BabyBear>,
> = OnceLock::new();
/// Lazy-loaded constants for `WIDTH = 24`
static BABYBEAR_POSEIDON2_24: OnceLock<
    Poseidon2Constants<24, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_24, BabyBear>,
> = OnceLock::new();

/// Get Poseidon2 constants for `WIDTH = 16`
pub fn get_poseidon2_16(
) -> &'static Poseidon2Constants<16, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_16, BabyBear> {
    BABYBEAR_POSEIDON2_16.get_or_init(|| {
        generate_round_constants::<16, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_16>(&RC16)
    })
}

/// Get Poseidon2 constants for `WIDTH = 24`
pub fn get_poseidon2_24(
) -> &'static Poseidon2Constants<24, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_24, BabyBear> {
    BABYBEAR_POSEIDON2_24.get_or_init(|| {
        generate_round_constants::<24, BABY_BEAR_POSEIDON2_PARTIAL_ROUNDS_24>(&RC24)
    })
}
