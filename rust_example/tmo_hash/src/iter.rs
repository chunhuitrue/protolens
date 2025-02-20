use std::{hash::Hash, marker::PhantomData, fmt};
use crate::tmo::*;

pub struct Iter<'a, K, V> 
where K: Eq + Hash
{
    pub(crate) done: usize,
    pub(crate) len: usize,
    pub(crate) next: *const Node<K, V>,
    pub(crate) phantom: PhantomData<&'a (K,V)>
}

impl<'a, K, V> Iterator for Iter<'a, K, V> 
where K: Eq + Hash
{
    type Item = (&'a K, &'a V);

    /// 仅从最老的一端开始
    fn next(&mut self) -> Option<(&'a K, &'a V)> {
        if self.done >= self.len {
            return None;
        }

        unsafe {
            let k = &(*(*self.next).key.as_ptr()) as &K;
            let v = &(*(*self.next).value.as_ptr()) as &V;
            self.next = (*self.next).next;
            self.done += 1;
            Some((k, v))
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.len - self.done))
    }
}

impl<K, V> fmt::Debug for Iter<'_, K, V>
where K: Eq + Hash + fmt::Debug
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.done >= self.len {
            write!(f, "Iter [{:?}/{:?}]", self.done, self.len)
        } else {
            let next = unsafe { &(*(*self.next).key.as_ptr())};
            write!(f, "Iter [{:?}/{:?} next: {:?}]", self.done, self.len, next)
        }
    }
}

impl<K, V> fmt::Display for Iter<'_, K, V>
where K: Eq + Hash + fmt::Debug + fmt::Display, V: fmt::Display
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.done >= self.len {
            write!(f, "Iter [{}/{}]", self.done, self.len)
        } else {
            let next = unsafe { &(*(*self.next).key.as_ptr())};
            write!(f, "Iter [{}/{} next: {}]", self.done, self.len, next)
        }
    }
}


