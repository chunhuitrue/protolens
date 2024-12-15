#![allow(unused)]

pub fn ntohl(value: u32) -> u32 {
    if cfg!(target_endian = "little") {
        value.to_be()
    } else {
        value
    }
}

pub fn ntohs(value: u16) -> u16 {
    if cfg!(target_endian = "little") {
        value.to_be()
    } else {
        value
    }
}

pub fn htonl(value: u32) -> u32 {
    if cfg!(target_endian = "big") {
        value       
    } else {
        value.to_be()            
    }
}

pub fn htons(value: u16) -> u16 {
    if cfg!(target_endian = "big") {
        value       
    } else {
        value.to_be()            
    }
}

mod tests {
    use super::*;

    #[test]
    #[cfg(target_endian = "little")]
    fn test_ntohl_little_endian() {
        let value: u32 = 0x12345678; // 网络
        let expected: u32 = 0x78563412; // 主机
        let converted_value = ntohl(value);
        assert_eq!(converted_value, expected);
    }

    #[test]
    #[cfg(target_endian = "big")]    
    fn test_ntohl_big_endian() {
        let value: u32 = 0x12345678;
        let expected: u32 = 0x12345678;
        let converted_value = ntohl(value);
        assert_eq!(converted_value, expected);
    }    
    
    #[test]
    #[cfg(target_endian = "little")]
    fn test_ntohs_little_endian() {
        let value: u16 = 0x1234; // 网络
        let expected: u16 = 0x3412; // 主机
        let converted_value = ntohs(value);
        assert_eq!(converted_value, expected);
    }

    #[test]
    #[cfg(target_endian = "big")]
    fn test_ntohs_big_endian() {
        let value: u16 = 0x1234; // 网络
        let expected: u16 = 0x1234; // 主机
        let converted_value = ntohs(value);
        assert_eq!(converted_value, expected);
    }

    #[test]
    #[cfg(target_endian = "little")]    
    fn test_htonl_little_endian() {
        let value: u32 = 0x12345678;
        let expected: u32 = 0x78563412;
        let converted_value = htonl(value);
        assert_eq!(converted_value, expected);
    }
    
    #[test]
    #[cfg(target_endian = "big")]    
    fn test_htonl_big_endian() {
        let value: u32 = 0x12345678;
        let expected: u32 = 0x12345678;
        let converted_value = htonl(value);
        assert_eq!(converted_value, expected);
    }

    #[test]
    #[cfg(target_endian = "little")]    
    fn test_htons_little_endian() {
        let value: u16 = 0x1234;
        let expected: u16 = 0x3412;
        let converted_value = htons(value);
        assert_eq!(converted_value, expected);
    }

    #[test]
    #[cfg(target_endian = "big")]    
    fn test_htons_big_endian() {
        let value: u16 = 0x1234;
        let expected: u16 = 0x1234;
        let converted_value = htons(value);
        assert_eq!(converted_value, expected);
    }
}
