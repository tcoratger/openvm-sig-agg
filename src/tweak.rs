use p3_baby_bear::{BabyBear, BabyBearParameters};
use p3_field::FieldAlgebra;
use p3_monty_31::MontyParameters;

/// The separator for message hash tweaks.
pub const TWEAK_SEPARATOR_FOR_MESSAGE_HASH: u8 = 0x02;
/// The separator for tree hash tweaks.
pub const TWEAK_SEPARATOR_FOR_TREE_HASH: u8 = 0x01;
/// The separator for chain hash tweaks.
pub const TWEAK_SEPARATOR_FOR_CHAIN_HASH: u8 = 0x00;

/// A trait for converting tweaks into field elements for Poseidon2 hashing.
pub trait TweakTransfformation<const TWEAK_LEN: usize> {
    /// Converts the tweak into field elements for Poseidon2 hashing.
    ///
    /// In Poseidon2, tweaks need to be encoded as elements of a finite field.
    fn to_field_elements(&self) -> [BabyBear; TWEAK_LEN];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TreeTweak {
    /// The depth of the node in the Merkle tree.
    level: u8,
    /// The position of the node in the given level.
    position: u32,
}

impl<const TWEAK_LEN: usize> TweakTransfformation<TWEAK_LEN> for TreeTweak {
    fn to_field_elements(&self) -> [BabyBear; TWEAK_LEN] {
        // Construct the tweak using bitwise shifts to encode level and position
        let mut tweak = ((self.level as u64) << 40) |
            ((self.position as u64) << 8) |
            (TWEAK_SEPARATOR_FOR_TREE_HASH as u64);

        // Prime modulus used to map the tweak into the finite field `BabyBear`
        let prime = BabyBearParameters::PRIME as u64;

        // Extract field elements efficiently by dividing tweak into chunks mod `prime`
        let mut result = [BabyBear::ZERO; TWEAK_LEN];
        for r in result.iter_mut() {
            if tweak == 0 {
                break;
            }
            *r = BabyBear::new((tweak % prime) as u32);
            tweak /= prime;
        }

        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainTweak {
    /// The key epoch (time interval) of the signature scheme.
    epoch: u32,
    /// Which chain the value belongs to.
    chain_index: u16,
    /// The position of the value in the chain.
    position: u16,
}

impl<const TWEAK_LEN: usize> TweakTransfformation<TWEAK_LEN> for ChainTweak {
    /// Converts the tweak into field elements for Poseidon2 hashing.
    ///
    /// In Poseidon2, tweaks need to be encoded as elements of a finite field.
    fn to_field_elements(&self) -> [BabyBear; TWEAK_LEN] {
        // Construct the tweak using bitwise shifts to encode epoch, chain_index and position
        let mut tweak = ((self.epoch as u128) << 40) |
            ((self.chain_index as u128) << 24) |
            ((self.position as u128) << 8) |
            TWEAK_SEPARATOR_FOR_CHAIN_HASH as u128;

        // Prime modulus used to map the tweak into the finite field `BabyBear`
        let prime = BabyBearParameters::PRIME as u128;

        // Extract field elements efficiently by dividing tweak into chunks mod `prime`
        let mut result = [BabyBear::ZERO; TWEAK_LEN];
        for r in result.iter_mut() {
            if tweak == 0 {
                break;
            }
            *r = BabyBear::new((tweak % prime) as u32);
            tweak /= prime;
        }

        result
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PoseidonTweak {
    Tree(TreeTweak),
    Chain(ChainTweak),
}

impl<const TWEAK_LEN: usize> TweakTransfformation<TWEAK_LEN> for PoseidonTweak {
    fn to_field_elements(&self) -> [BabyBear; TWEAK_LEN] {
        match self {
            PoseidonTweak::Tree(tree_tweak) => tree_tweak.to_field_elements(),
            PoseidonTweak::Chain(chain_tweak) => chain_tweak.to_field_elements(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_tweak_to_field_elements_small_values() {
        let tweak = TreeTweak { level: 1, position: 2 };
        let field_elements = tweak.to_field_elements();
        assert_eq!(field_elements, [BabyBear::new(268435423), BabyBear::new(546)]);
    }

    #[test]
    fn test_tree_tweak_to_field_elements_random_values() {
        assert_eq!(
            TreeTweak { level: u8::MAX, position: u32::MAX }.to_field_elements(),
            [
                BabyBear::new(268295391),
                BabyBear::new(139810),
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO
            ]
        );

        assert_eq!(
            TreeTweak { level: 25, position: 26282 }.to_field_elements(),
            [BabyBear::new(677803180), BabyBear::new(13653),]
        );
    }

    #[test]
    fn test_tree_tweak_to_field_elements_edge_cases() {
        let tweak = TreeTweak { level: 0, position: 0 };
        let field_elements = tweak.to_field_elements();
        // Only the separator should be set
        assert_eq!(
            field_elements,
            [BabyBear::new(TWEAK_SEPARATOR_FOR_TREE_HASH as u32), BabyBear::ZERO]
        );
    }

    #[test]
    fn test_chain_tweak_to_field_elements_small_values() {
        let tweak = ChainTweak { epoch: 1, chain_index: 2, position: 3 };
        let field_elements = tweak.to_field_elements();
        assert_eq!(field_elements, [BabyBear::new(301990110), BabyBear::new(546)]);
    }

    #[test]
    fn test_chain_tweak_to_field_elements_random_values() {
        let tweak = ChainTweak { epoch: u32::MAX, chain_index: u16::MAX, position: u16::MAX };
        let field_elements = tweak.to_field_elements();
        assert_eq!(
            field_elements,
            [
                BabyBear::new(98427243),
                BabyBear::new(170006792),
                BabyBear::new(1165),
                BabyBear::ZERO
            ]
        );
    }

    #[test]
    fn test_chain_tweak_to_field_elements_edge_cases() {
        let tweak = ChainTweak { epoch: 0, chain_index: 0, position: 0 };
        let field_elements = tweak.to_field_elements();
        // Only the separator should be set
        assert_eq!(
            field_elements,
            [BabyBear::new(TWEAK_SEPARATOR_FOR_CHAIN_HASH as u32), BabyBear::ZERO]
        );
    }
}
