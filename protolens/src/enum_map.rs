#![allow(unused)]
use crate::ParserFactory;
use crate::packet::*;

pub(crate) const MAX_ENUM: usize = 128;

pub struct EnumMap<V> {
    data: Vec<Option<V>>,
}

impl<V> EnumMap<V> {
    pub fn new() -> Self {
        let mut data = Vec::with_capacity(MAX_ENUM);
        for _ in 0..MAX_ENUM {
            data.push(None);
        }
        EnumMap { data }
    }

    pub fn insert(&mut self, key: L7Proto, value: V) {
        let idx = key as usize;
        if idx >= self.data.len() {
            return;
        }
        self.data[idx] = Some(value);
    }

    pub fn get(&self, key: &L7Proto) -> Option<&V> {
        let idx = *key as usize;
        if idx < self.data.len() {
            self.data[idx].as_ref()
        } else {
            None
        }
    }

    pub fn contains_key(&self, key: &L7Proto) -> bool {
        let idx = *key as usize;
        idx < self.data.len() && self.data[idx].is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MyPacket;

    #[test]
    fn test_l7proto_values() {
        assert_eq!(L7Proto::OrdPacket as u32, 0);
        assert_eq!(L7Proto::Smtp as u32, 1);
        assert_eq!(L7Proto::Pop3 as u32, 2);
        #[cfg(test)]
        {
            assert_eq!(L7Proto::RawPacket as u32, 5);
            assert_eq!(L7Proto::Byte as u32, 6);
        }
    }

    #[test]
    fn test_enum_map_basic() {
        let mut map = EnumMap::<i32>::new();

        map.insert(L7Proto::OrdPacket, 1);
        map.insert(L7Proto::Smtp, 2);

        assert_eq!(map.get(&L7Proto::OrdPacket), Some(&1));
        assert_eq!(map.get(&L7Proto::Smtp), Some(&2));
        assert_eq!(map.get(&L7Proto::Unknown), None);
    }

    #[test]
    fn test_enum_map_contains_key() {
        let mut map = EnumMap::<String>::new();

        map.insert(L7Proto::OrdPacket, "test".to_string());

        assert!(map.contains_key(&L7Proto::OrdPacket));
        assert!(!map.contains_key(&L7Proto::Smtp));
    }

    #[test]
    fn test_enum_map_overwrite() {
        let mut map = EnumMap::<i32>::new();

        map.insert(L7Proto::OrdPacket, 1);
        map.insert(L7Proto::OrdPacket, 2);

        assert_eq!(map.get(&L7Proto::OrdPacket), Some(&2));
    }

    #[test]
    fn test_enum_map_bounds() {
        let mut map = EnumMap::<i32>::new();

        assert_eq!(map.get(&L7Proto::OrdPacket), None);

        map.insert(L7Proto::OrdPacket, 1);
        assert_eq!(map.get(&L7Proto::OrdPacket), Some(&1));

        let large_idx = L7Proto::Unknown;
        map.insert(large_idx, 100);
        assert!(map.get(&large_idx).is_some());
    }

    #[test]
    fn test_enum_map_multiple_types() {
        // 测试不同类型的值
        let mut map_string = EnumMap::<String>::new();
        let mut map_vec = EnumMap::<Vec<i32>>::new();

        map_string.insert(L7Proto::OrdPacket, "hello".to_string());
        map_vec.insert(L7Proto::OrdPacket, vec![1, 2, 3]);

        assert_eq!(
            map_string.get(&L7Proto::OrdPacket),
            Some(&"hello".to_string())
        );
        assert_eq!(map_vec.get(&L7Proto::OrdPacket), Some(&vec![1, 2, 3]));
    }
}
