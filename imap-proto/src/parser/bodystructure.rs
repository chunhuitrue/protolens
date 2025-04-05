use crate::ContentEncoding;
use std::collections::HashMap;

use crate::types::BodyStructure;
/// An utility parser helping to find the appropriate
/// section part from a FETCH response.
pub struct BodyStructParser<'a> {
    root: &'a BodyStructure<'a>,
    prefix: Vec<u32>,
    iter: u32,
    map: HashMap<Vec<u32>, &'a BodyStructure<'a>>,
}

impl<'a> BodyStructParser<'a> {
    /// Returns a new parser
    ///
    /// # Arguments
    ///
    /// * `root` - The root of the `BodyStructure response.
    pub fn new(root: &'a BodyStructure<'a>) -> Self {
        let mut parser = BodyStructParser {
            root,
            prefix: vec![],
            iter: 1,
            map: HashMap::new(),
        };

        parser.parse(parser.root);
        parser
    }

    /// Search particular element within the bodystructure.
    ///
    /// # Arguments
    ///
    /// * `func` - The filter used to search elements within the bodystructure.
    pub fn search<F>(&self, func: F) -> Option<Vec<u32>>
    where
        F: Fn(&'a BodyStructure<'a>) -> bool,
    {
        let elem: Vec<_> = self
            .map
            .iter()
            .filter_map(|(k, v)| {
                if func(v) {
                    let slice: &[u32] = k;
                    Some(slice)
                } else {
                    None
                }
            })
            .collect();
        elem.first().map(|a| a.to_vec())
    }

    /// Reetr
    fn parse(&mut self, node: &'a BodyStructure) {
        match node {
            BodyStructure::Multipart { bodies, .. } => {
                let vec = self.prefix.clone();
                self.map.insert(vec, node);

                for (i, n) in bodies.iter().enumerate() {
                    self.iter += i as u32;
                    self.prefix.push(self.iter);
                    self.parse(n);
                    self.prefix.pop();
                }
                self.iter = 1;
            }
            _ => {
                let vec = self.prefix.clone();
                self.map.insert(vec, node);
            }
        };
    }
}

pub struct BodyStructParser2 {
    root: Box<BodyStructure<'static>>,
    prefix: Vec<u32>,
    iter: u32,
    map: HashMap<Vec<u32>, *const BodyStructure<'static>>,
}

impl BodyStructParser2 {
    pub fn new(root: BodyStructure<'static>) -> Self {
        let mut parser = BodyStructParser2 {
            root: Box::new(root),
            prefix: vec![],
            iter: 1,
            map: HashMap::new(),
        };

        parser.parse();
        parser
    }

    pub fn search<F>(&self, func: F) -> Option<Vec<u32>>
    where
        F: Fn(&BodyStructure<'static>) -> bool,
    {
        let elem: Vec<_> = self
            .map
            .iter()
            .filter_map(|(k, v)| unsafe {
                if func(&**v) {
                    let slice: &[u32] = k;
                    Some(slice)
                } else {
                    None
                }
            })
            .collect();
        elem.first().map(|a| a.to_vec())
    }

    fn parse(&mut self) {
        let root_ptr = &*self.root as *const _;
        self.parse_node(root_ptr);
    }

    fn parse_node(&mut self, node: *const BodyStructure<'static>) {
        let vec = self.prefix.clone();
        self.map.insert(vec, node);

        unsafe {
            if let BodyStructure::Multipart { bodies, .. } = &*node {
                let body_ptrs: Vec<_> = bodies.iter().map(|n| n as *const _).collect();

                for (i, &n) in body_ptrs.iter().enumerate() {
                    self.iter = (i + 1) as u32;
                    self.prefix.push(self.iter);
                    self.parse_node(n);
                    self.prefix.pop();
                }
            }
        }
    }

    pub fn get_transfer_encoding(&self, path: &[u32]) -> Option<ContentEncoding<'static>> {
        self.map.get(path).and_then(|&body| unsafe {
            match &*body {
                BodyStructure::Basic { other, .. } => Some(other.transfer_encoding.to_owned()),
                BodyStructure::Text { other, .. } => Some(other.transfer_encoding.to_owned()),
                BodyStructure::Message { other, .. } => Some(other.transfer_encoding.to_owned()),
                BodyStructure::Multipart { .. } => None,
            }
        })
    }
}
