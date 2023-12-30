extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;

#[proc_macro]
pub fn bpf_defaults(_item: TokenStream) -> TokenStream {
    return quote! {
        #[map]
        static SETTINGS_MAP: aya_bpf::maps::HashMap<u64, u64> = aya_bpf::maps::HashMap::with_max_entries(3, 0);

        fn get_sample_rate() -> u64 {
            return match unsafe { SETTINGS_MAP.get(&trac_common::SAMEPLE_RATE_KEY) } {
                None => 500,
                Some(i) => *i,
            }
        }

        fn get_current_bucket() -> u32 {
            let timestamp = unsafe { aya_bpf::helpers::bpf_ktime_get_boot_ns() };

            match unsafe { SETTINGS_MAP.get(&trac_common::START_TIME_KEY) } {
                None => 0,
                Some(i) => {
                    ((timestamp - i) / trac_common::MS_IN_NS / get_sample_rate()) as u32
                }
            }
        }
    }.into();
}
