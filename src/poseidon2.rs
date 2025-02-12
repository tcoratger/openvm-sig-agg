use num_bigint::BigUint;
use p3_baby_bear::{BabyBear, BabyBearParameters, Poseidon2BabyBear};
use p3_field::FieldAlgebra;
use p3_monty_31::MontyParameters;
use p3_symmetric::Permutation;

#[derive(Debug)]
pub struct Assert<const COND: bool>;

pub trait IsTrue {}
impl IsTrue for Assert<true> {}

pub type Poseidon2BabyBearLong = Poseidon2BabyBear<24>;
pub type Poseidon2BabyBearShort = Poseidon2BabyBear<16>;

/// Trait to constrain valid WIDTH values
pub trait Poseidon2BabyBearValidWidth {
    const WIDTH: usize;
}

impl Poseidon2BabyBearValidWidth for Poseidon2BabyBearShort {
    const WIDTH: usize = 16;
}

impl Poseidon2BabyBearValidWidth for Poseidon2BabyBearLong {
    const WIDTH: usize = 24;
}

/// Applies the Poseidon2 permutation to a padded input.
///
/// # Overview:
/// - **Padding:** If the input `x` has fewer elements than `WIDTH`, it is zero-padded.
/// - **Permutation:** The Poseidon2 permutation is then applied to the padded input.
///
/// # Paper Reference:
/// This function computes `PoseidonPerm(x)`.
/// It ensures that `x` is first expanded to a valid `WIDTH` before applying Poseidon2.
pub fn poseidon2_padded_permute<I>(instance: &I, x: &[BabyBear]) -> [BabyBear; I::WIDTH]
where
    I: Poseidon2BabyBearValidWidth + Permutation<[BabyBear; I::WIDTH]>,
{
    assert!(x.len() <= I::WIDTH, "Input length must be less than WIDTH");

    // Pad input with zeroes if necessary
    let mut padded_x = [BabyBear::ZERO; I::WIDTH];
    padded_x[..x.len()].copy_from_slice(x);

    // Apply Poseidon permutation
    instance.permute_mut(&mut padded_x);
    padded_x
}

/// Implements the Poseidon2 **Compression Mode** hashing function.
///
/// # Overview:
/// - Computes `PoseidonCompress(x) = Truncate_u(PoseidonPerm(x) + x)`.
/// - The input is permuted and then truncated to the first `OUT_LEN` elements.
///
/// # Paper Reference:
/// Compression mode is the **more efficient** option, as it directly maps `t` inputs to `u` outputs
/// without requiring iterative absorption, unlike sponge mode.
pub fn poseidon2_compress<const OUT_LEN: usize, I>(
    poseidon_instance: &I,
    x: &[BabyBear],
) -> [BabyBear; OUT_LEN]
where
    I: Poseidon2BabyBearValidWidth + Permutation<[BabyBear; I::WIDTH]>,
{
    assert!(x.len() >= OUT_LEN, "Input length must be greater than or equal to OUT_LEN");

    // Apply Poseidon2 permutation
    let permuted_x = poseidon2_padded_permute(poseidon_instance, x);

    // Compute element-wise addition and truncate to OUT_LEN
    //
    // This leads to PoseidonCompress(x) = Truncate(PoseidonPermute(x) + x)
    core::array::from_fn(|i| permuted_x[i] + x[i])
}

/// Implements the Poseidon2 **Sponge Mode** hashing function.
///
/// # Overview:
/// - **Absorption:** The input `x` is divided into chunks of `rate`, and each chunk is absorbed.
/// - **Permutation:** After every absorption step, Poseidon2 permutation is applied.
/// - **Squeezing:** The state is iteratively extracted to produce `OUT_LEN` elements.
///
/// # Paper Reference:
/// This mode is **more flexible** than compression mode but has **higher computational cost**.
/// - It is used when `x.len()` exceeds `t = {4, 8, 12, 16, 20, 24}`.
/// - Requires padding to align input to a multiple of `rate`.
pub fn poseidon2_sponge<const OUT_LEN: usize, const CAPACITY: usize, I>(
    poseidon_instance: &I,
    capacity_value: &[BabyBear; CAPACITY],
    x: &[BabyBear],
) -> [BabyBear; OUT_LEN]
where
    I: Poseidon2BabyBearValidWidth + Permutation<[BabyBear; I::WIDTH - CAPACITY]>,
    Assert<{ I::WIDTH > CAPACITY }>: IsTrue,
    [(); I::WIDTH - CAPACITY]:,
{
    // Compute the rate (available absorption space)
    let rate = I::WIDTH - CAPACITY;

    // Pad input to a multiple of `rate`
    let extra_elements = (rate - (x.len() % rate)) % rate;
    let mut input_vector = x.to_vec().clone();
    input_vector.resize(x.len() + extra_elements, BabyBear::ZERO);

    // Initialize state with `capacity_value`
    let mut state =
        core::array::from_fn(|i| capacity_value.get(i).copied().unwrap_or(BabyBear::ZERO));

    // Absorption phase
    for chunk in input_vector.chunks_exact(rate) {
        state.iter_mut().zip(chunk).for_each(|(s, &c)| *s += c);
        poseidon_instance.permute_mut(&mut state);
    }

    // // Step 5: Squeeze phase - extract output
    // let mut out = [BabyBear::ZERO; OUT_LEN];
    // let mut out_index = 0;

    // while out_index < OUT_LEN {
    //     let len = (OUT_LEN - out_index).min(rate);
    //     out[out_index..out_index + len].copy_from_slice(&state[..len]);
    //     out_index += len;
    //     poseidon_instance.permute_mut(&mut state);
    // }

    // out

    // Squeeze phase - extract output
    let mut out = vec![];
    while out.len() < OUT_LEN {
        out.extend_from_slice(&state[..rate]);
        poseidon_instance.permute_mut(&mut state);
    }
    out.as_slice()[..OUT_LEN].try_into().expect("Length mismatch")
}

pub fn poseidon_safe_domain_separator<const OUT_LEN: usize, I>(
    poseidon_instance: &I,
    params: &[usize],
) -> [BabyBear; OUT_LEN]
where
    I: Poseidon2BabyBearValidWidth + Permutation<[BabyBear; I::WIDTH]>,
{
    // Turn params into a big integer
    let domain_uint = params.iter().fold(BigUint::ZERO, |acc, &item| {
        acc * BigUint::from(((1 as u64) << 32) as u64) + (item as u32)
    });

    // create the Poseidon input by interpreting the number in base-p
    let mut input = vec![BabyBear::ZERO; I::WIDTH];
    input.iter_mut().fold(domain_uint, |acc, item| {
        let tmp = acc.clone() % BigUint::from(BabyBearParameters::PRIME);
        *item = BabyBear::new(*tmp.to_u32_digits().first().unwrap_or(&0));
        (acc - tmp) / (BigUint::from(BabyBearParameters::PRIME))
    });
    // now run Poseidon
    poseidon2_compress::<OUT_LEN, I>(poseidon_instance, &input)
}
