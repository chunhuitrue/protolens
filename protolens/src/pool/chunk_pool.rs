use crate::pool::*;
use libc::{MAP_ANON, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap, munmap};
use std::cell::RefCell;
use std::os::raw::c_void;
use std::pin::Pin;
use std::ptr;

const CHUNK_SIZE: usize = 2 * 1024 * 1024;

struct Chunk {
    next: *mut Chunk,
}

#[derive(Clone)]
pub(crate) struct ChunkPool {
    chunk_list: RefCell<*mut Chunk>,

    mem_total: RefCell<usize>,
    mem_ptr: RefCell<*mut u8>,
}

impl ChunkPool {
    pub(crate) fn new(mem_total: usize, _obj_sizes: Vec<usize>) -> Self {
        ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),

            mem_total: RefCell::new(mem_total),
            mem_ptr: RefCell::new(ptr::null_mut()),
        }
    }

    pub(crate) fn init(&self) -> bool {
        if !self.mem_init() {
            return false;
        }
        self.chunk_list_init()
    }

    pub(crate) fn alloc<T, F>(&self, init: F, pool_impl: PoolImpl) -> PoolBox<T>
    where
        F: FnOnce() -> T,
    {
        let ptr = Box::into_raw(Box::new(init()));
        PoolBox {
            ptr,
            pool: pool_impl,
        }
    }

    pub(crate) fn alloc_future<F>(
        &self,
        future: F,
        pool_impl: PoolImpl,
    ) -> Pin<PoolBox<dyn Future<Output = F::Output>>>
    where
        F: Future + 'static,
    {
        let future = Box::new(future);
        let ptr = Box::into_raw(future) as *mut dyn Future<Output = F::Output>;
        unsafe {
            Pin::new_unchecked(PoolBox {
                ptr,
                pool: pool_impl,
            })
        }
    }

    fn chunk_list_init(&self) -> bool {
        let mem_ptr = *self.mem_ptr.borrow();
        if mem_ptr.is_null() {
            return false;
        }

        let total_size = *self.mem_total.borrow();
        let chunk_count = total_size / CHUNK_SIZE;
        *self.chunk_list.borrow_mut() = ptr::null_mut();

        for i in (0..chunk_count).rev() {
            let chunk_ptr = unsafe { mem_ptr.add(i * CHUNK_SIZE) as *mut Chunk };
            unsafe {
                (*chunk_ptr).next = *self.chunk_list.borrow();
                *self.chunk_list.borrow_mut() = chunk_ptr;
            }
        }
        true
    }

    #[allow(dead_code)]
    fn chunk_get(&self) -> Option<*mut Chunk> {
        let mut chunk_list = self.chunk_list.borrow_mut();
        if chunk_list.is_null() {
            return None;
        }

        let chunk = *chunk_list;
        unsafe {
            *chunk_list = (*chunk).next;
        }

        Some(chunk)
    }

    #[allow(dead_code)]
    fn chunk_put(&self, chunk: *mut Chunk) {
        if chunk.is_null() {
            return;
        }

        let mut chunk_list = self.chunk_list.borrow_mut();
        unsafe {
            (*chunk).next = *chunk_list;
        }
        *chunk_list = chunk;
    }

    fn mem_init(&self) -> bool {
        let total_size = *self.mem_total.borrow();
        let chunks_needed = total_size.div_ceil(CHUNK_SIZE);
        let aligned_size = chunks_needed * CHUNK_SIZE;
        *self.mem_total.borrow_mut() = aligned_size;

        if *self.mem_total.borrow() < CHUNK_SIZE {
            return false;
        }

        let ptr = unsafe {
            mmap(
                ptr::null_mut(),          // 让系统选择地址
                *self.mem_total.borrow(), // 分配的内存大小
                PROT_READ | PROT_WRITE,   // 读写权限
                MAP_PRIVATE | MAP_ANON,   // 私有匿名映射
                -1,                       // 匿名映射不需要文件描述符
                0,                        // 偏移量为0
            )
        };
        if ptr == libc::MAP_FAILED {
            return false;
        }

        *self.mem_ptr.borrow_mut() = ptr as *mut u8;
        true
    }

    fn mem_free(&mut self) {
        let ptr = *self.mem_ptr.borrow();
        unsafe {
            munmap(ptr as *mut c_void, *self.mem_total.borrow());
        }
        *self.mem_ptr.borrow_mut() = ptr::null_mut();
    }
}

impl Drop for ChunkPool {
    fn drop(&mut self) {
        self.mem_free();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::ptr;

    #[test]
    fn test_mem_init_success() {
        // 内存大小等于CHUNK_SIZE
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),

            mem_total: RefCell::new(CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        let result = pool.mem_init();
        assert!(result);
        assert!(!(*pool.mem_ptr.borrow()).is_null());
        assert_eq!(*pool.mem_total.borrow(), CHUNK_SIZE);

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_mem_init_with_unaligned_size() {
        // 存大小为CHUNK_SIZE + 1000（不是CHUNK_SIZE的整数倍）
        let unaligned_size = CHUNK_SIZE + 1000;
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),

            mem_total: RefCell::new(unaligned_size),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        let result = pool.mem_init();
        assert!(result);
        assert!(!(*pool.mem_ptr.borrow()).is_null());
        assert_eq!(*pool.mem_total.borrow(), 2 * CHUNK_SIZE);

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_mem_init_with_small_size() {
        // 内存大小小于CHUNK_SIZE
        let small_size = CHUNK_SIZE / 2;
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),

            mem_total: RefCell::new(small_size),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        let result = pool.mem_init();
        assert!(result);
        assert!(!(*pool.mem_ptr.borrow()).is_null());
        // 验证内存大小已经对齐到CHUNK_SIZE
        assert_eq!(*pool.mem_total.borrow(), CHUNK_SIZE);

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_mem_init_with_zero_size() {
        // 内存大小为0
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),

            mem_total: RefCell::new(0),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        let result = pool.mem_init();
        assert!(!result);
    }

    #[test]
    fn test_mem_chunk_list_success() {
        // 创建一个包含2个chunk的内存池
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(2 * CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        let init_result = pool.mem_init();
        assert!(init_result);

        let result = pool.chunk_list_init();
        assert!(result);

        let chunk_list = *pool.chunk_list.borrow();
        assert!(!chunk_list.is_null());

        unsafe {
            let first_chunk = chunk_list;
            assert!(!first_chunk.is_null());
            let second_chunk = (*first_chunk).next;
            assert!(!second_chunk.is_null());
            assert!((*second_chunk).next.is_null());

            // 验证chunk之间的地址差是CHUNK_SIZE
            let first_addr = first_chunk as usize;
            let second_addr = second_chunk as usize;
            assert_eq!(second_addr - first_addr, CHUNK_SIZE);
        }

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_mem_chunk_list_with_null_mem_ptr() {
        // 创建一个内存指针为null的内存池
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        // 没有执行pool.mem_init()
        // 尝试创建chunk链表，应该失败
        let result = pool.chunk_list_init();
        assert!(!result);
        assert!((*pool.chunk_list.borrow()).is_null());
    }

    #[test]
    fn test_mem_chunk_list_multiple_chunks() {
        // 创建一个包含4个chunk的内存池
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(4 * CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        let init_result = pool.mem_init();
        assert!(init_result);
        let result = pool.chunk_list_init();
        assert!(result);
        let chunk_list = *pool.chunk_list.borrow();
        assert!(!chunk_list.is_null());

        // 验证链表中有4个chunk，并且它们按照正确的顺序链接
        unsafe {
            let mut current = chunk_list;
            let mut count = 0;
            let mut prev_addr = 0;

            while !current.is_null() {
                let current_addr = current as usize;

                // 如果不是第一个chunk，验证地址差是CHUNK_SIZE
                if prev_addr != 0 {
                    assert_eq!(current_addr - prev_addr, CHUNK_SIZE);
                }

                prev_addr = current_addr;
                current = (*current).next;
                count += 1;
            }
            assert_eq!(count, 4);
        }

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_init_creates_chunk_list() {
        // 测试init方法是否正确创建了chunk链表
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(2 * CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        let result = pool.init();
        assert!(result);
        let chunk_list = *pool.chunk_list.borrow();
        assert!(!chunk_list.is_null());

        // 验证链表中有2个chunk
        unsafe {
            let mut count = 0;
            let mut current = chunk_list;

            while !current.is_null() {
                current = (*current).next;
                count += 1;
            }
            assert_eq!(count, 2);
        }

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_chunk_get_and_put() {
        // 创建一个包含2个chunk的内存池
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(2 * CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        assert!(pool.mem_init());
        assert!(pool.chunk_list_init());

        let chunk1 = pool.chunk_get();
        assert!(chunk1.is_some());
        let chunk1 = chunk1.unwrap();

        let chunk2 = pool.chunk_get();
        assert!(chunk2.is_some());
        let chunk2 = chunk2.unwrap();

        // 此时链表应该为空
        assert!(pool.chunk_get().is_none());

        pool.chunk_put(chunk1);

        // 现在应该可以再次获取一个chunk
        let chunk3 = pool.chunk_get();
        assert!(chunk3.is_some());
        assert_eq!(chunk3.unwrap(), chunk1);

        // 链表再次为空
        assert!(pool.chunk_get().is_none());

        // 将chunk2放回链表
        pool.chunk_put(chunk2);

        // 现在应该可以再次获取一个chunk
        let chunk4 = pool.chunk_get();
        assert!(chunk4.is_some());
        assert_eq!(chunk4.unwrap(), chunk2);

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_chunk_put_null() {
        // 测试将null放回链表的情况
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        assert!(pool.mem_init());
        assert!(pool.chunk_list_init());

        let chunk = pool.chunk_get();
        assert!(chunk.is_some());

        assert!(pool.chunk_get().is_none());

        // 尝试将null放回链表，不应该有任何影响
        pool.chunk_put(ptr::null_mut());
        assert!(pool.chunk_get().is_none());

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }

    #[test]
    fn test_chunk_get_from_empty_list() {
        // 测试从空链表获取chunk的情况
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        // 不初始化内存和chunk链表，直接尝试获取chunk
        let chunk = pool.chunk_get();
        assert!(chunk.is_none());
    }

    #[test]
    fn test_chunk_put_and_get_multiple() {
        // 测试多次放入和获取chunk
        let pool = ChunkPool {
            chunk_list: RefCell::new(ptr::null_mut()),
            mem_total: RefCell::new(2 * CHUNK_SIZE),
            mem_ptr: RefCell::new(ptr::null_mut()),
        };

        assert!(pool.mem_init());
        assert!(pool.chunk_list_init());

        // 获取所有chunk
        let chunk1 = pool.chunk_get().unwrap();
        let chunk2 = pool.chunk_get().unwrap();
        assert!(pool.chunk_get().is_none());

        // 按照不同的顺序放回和获取
        pool.chunk_put(chunk1);
        pool.chunk_put(chunk2);

        // 现在链表中应该有两个chunk，且chunk2在前（因为后放入）
        let retrieved_chunk1 = pool.chunk_get().unwrap();
        let retrieved_chunk2 = pool.chunk_get().unwrap();
        assert_eq!(retrieved_chunk1, chunk2);
        assert_eq!(retrieved_chunk2, chunk1);
        assert!(pool.chunk_get().is_none());

        unsafe {
            munmap(
                *pool.mem_ptr.borrow() as *mut c_void,
                *pool.mem_total.borrow(),
            );
        }
    }
}
