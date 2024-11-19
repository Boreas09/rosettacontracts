/// Deserializes a span of felt252 values into an array of bytes.
///
/// # Arguments
///
/// * `self` - A span of felt252 values to deserialize.
///
/// # Returns
///
/// * `Option<Array<u8>>` - The deserialized bytes if successful, or None if deserialization fails.
pub fn deserialize_bytes(self: Span<felt252>) -> Option<Array<u8>> {
    let mut bytes: Array<u8> = Default::default();

    for item in self {
        let v: Option<u8> = (*item).try_into();

        match v {
            Option::Some(v) => { bytes.append(v); },
            Option::None => { break; }
        }
    };

    // it means there was an error in the above loop
    if (bytes.len() != self.len()) {
        Option::None
    } else {
        Option::Some(bytes)
    }
}

/// Serializes a span of bytes into an array of felt252 values.
///
/// # Arguments
///
/// * `self` - A span of bytes to serialize.
///
/// # Returns
///
/// * `Array<felt252>` - The serialized bytes as an array of felt252 values.
pub fn serialize_bytes(self: Span<u8>) -> Array<felt252> {
    let mut array: Array<felt252> = Default::default();

    for item in self {
        let value: felt252 = (*item).into();
        array.append(value);
    };

    array
}

/// Computes the y-parity value for EIP-155 signature recovery.
///
/// # Arguments
///
/// * `v` - The v value from the signature.
/// * `chain_id` - The chain ID used for EIP-155 signature recovery.
///
/// # Returns
///
/// * `Option<bool>` - The computed y-parity value if valid, or None if invalid.
pub fn compute_y_parity(v: u128, chain_id: u64) -> Option<bool> {
    let y_parity = v - (chain_id.into() * 2 + 35);
    if (y_parity == 0 || y_parity == 1) {
        return Option::Some(y_parity == 1);
    }

    return Option::None;
}

pub fn u256_split_into_u8s(val: u256) -> Span<u8> {
    let mut splitted = ArrayTrait::<u8>::new();
    let mut value = val;
    while value > 0 {
        let byte: u8 = value & 0xFF;
        splitted.append(byte);
        value = value / 0x10000000;
    };

    splitted.span()
}


#[cfg(test)]
mod tests {
    use crate::utils::serialization::{deserialize_bytes};

    #[test]
    fn test_bytes_deserialize() {
        let arr = array![0xFF, 0xAB];

        let deserialized_bytes = deserialize_bytes(arr.span()).unwrap();

        assert_eq!(*deserialized_bytes.at(0), 0xFF);
    }

    #[test]
    fn test_u256_split_once() {
        let data: u256 = 0x12884723;

        let splitted_data: Span<u8> = u256_split_into_u8s(data);

        assert_eq!(*splitted_data.at(0), 0x12);
        assert_eq!(*splitted_data.at(1), 0x88);
        assert_eq!(*splitted_data.at(2), 0x47);
        assert_eq!(*splitted_data.at(3), 0x23);
    }
}