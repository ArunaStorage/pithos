pub fn set_flag_bit(target: &mut u64, flag_id: u8) {
    *target |= 1 << flag_id
}

pub fn unset_flag_bit(target: &mut u64, flag_id: u8) {
    *target &= !(1 << flag_id) // 1101 & 1111 = 1101
}

pub fn is_flag_bit_set(target: &u64, flag_id: u8) -> bool {
    target >> flag_id & 1 == 1 // 11011101 >> 4 = 1101 & 0001 = 0001 == 0001 -> true
}

pub fn set_flag_bit_u8(target: &mut u8, flag_id: u8) {
    *target |= 1 << flag_id
}

pub fn unset_flag_bit_u8(target: &mut u8, flag_id: u8) {
    *target &= !(1 << flag_id) // 1101 & 1111 = 1101
}

pub fn is_flag_bit_set_u8(target: &u8, flag_id: u8) -> bool {
    target >> flag_id & 1 == 1 // 11011101 >> 4 = 1101 & 0001 = 0001 == 0001 -> true
}

pub fn set_flag_bit_u16(target: &mut u16, flag_id: u16) {
    *target |= 1 << flag_id
}

pub fn unset_flag_bit_u16(target: &mut u16, flag_id: u16) {
    *target &= !(1 << flag_id) // 1101 & 1111 = 1101
}

pub fn is_flag_bit_set_u16(target: &u16, flag_id: u16) -> bool {
    target >> flag_id & 1 == 1 // 11011101 >> 4 = 1101 & 0001 = 0001 == 0001 -> true
}
