extern crate proc_macro;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use proc_macro_error::{abort, proc_macro_error};
use syn::{
    Result, ItemFn
};
use quote::quote;

pub(crate) struct Profiling {
    item: ItemFn,
}

impl Profiling {
    pub(crate) fn parse(item: TokenStream2) -> Result<Profiling> {
        let item = syn::parse2(item)?;
        Ok(Profiling {
            item,
        })
    }

    #[cfg(feature = "profiling")]
    pub(crate) fn expand(&self) -> Result<TokenStream2> {
        let fn_vis = &self.item.vis;
        let fn_name = self.item.sig.ident.clone();
        let item = &self.item;
        let fn_params = &self.item.sig.inputs;
        // let fn_input = &self.item.sig;
        Ok(quote! {
            #fn_vis fn #fn_name(#fn_params) -> u32 {
                fn store_profiling_data(start: u64, isInner: bool) {
                    let stop = unsafe { aya_bpf::helpers::bpf_ktime_get_boot_ns() };
                    let diff = stop - start;
                    let mut bucket: u32 = 0;
                    let mut key: u32 = 0;

                    match BPF_PROFILING_STATE_MAP.get_ptr_mut(key) {
                        None => {},
                        Some(i) => {
                            if unsafe { *i } == 0 {
                                unsafe { *i = start };
                            } else {
                                bucket = unsafe { ((start - *i) / (1000000000 as u64)) as u32 };
                            }
                        }
                    }

                    match BPF_PROFILING_MAP.get_ptr_mut(bucket) {
                        None => {},
                        Some(i) => {
                            if isInner {
                                unsafe { (*i).count += 1 };
                                unsafe { (*i).inner_nanosecs += diff };
                            } else {
                                unsafe { (*i).outer_nanosecs += diff };
                            }
                        }
                    }

                    key = 1;
                    match BPF_PROFILING_STATE_MAP.get_ptr_mut(key) {
                        None => {},
                        Some(i) => {
                            unsafe { *i = bucket as u64 };
                        }
                    }
                }

                let start_outer = unsafe { aya_bpf::helpers::bpf_ktime_get_boot_ns() };
                let start_inner = unsafe { aya_bpf::helpers::bpf_ktime_get_boot_ns() };
                let ret = #fn_name(ctx);
                store_profiling_data(start_inner, true);
                store_profiling_data(start_outer, false);
                return ret;

                #item
            }
        })
    }
    

    #[cfg(not(feature = "profiling"))]
    pub(crate) fn expand(&self) -> Result<TokenStream2> {
        let item = &self.item;
        Ok(quote! {
            #item
        })
    }
    
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn profiling(_: TokenStream, item: TokenStream) -> TokenStream {
    match Profiling::parse(item.into()) {
        Ok(prog) => prog
            .expand()
            .unwrap_or_else(|err| abort!(err.span(), "{}", err))
            .into(),
        Err(err) => abort!(err.span(), "{}", err),
    }
}

#[cfg(feature = "profiling")]
#[proc_macro]
pub fn profiling_maps_def(_item: TokenStream) -> TokenStream {
    return quote! {
        struct ProfilingEntry {
            count: u64,
            inner_nanosecs: u64,
            outer_nanosecs: u64,
        }
        
        #[map]
        static BPF_PROFILING_STATE_MAP: aya_bpf::maps::Array<u64> = aya_bpf::maps::Array::with_max_entries(2, 0);
        
        #[map]
        static BPF_PROFILING_MAP: aya_bpf::maps::Array<ProfilingEntry> = aya_bpf::maps::Array::with_max_entries(65536, 0);
    }.into();
}

#[cfg(not(feature = "profiling"))]
#[proc_macro]
pub fn profiling_maps_def(_item: TokenStream) -> TokenStream {
    return quote! {

    }.into();
}


