extern crate proc_macro;

use proc_macro::TokenStream;

use quote::quote;
use syn::parse::{Parse, ParseStream, Result};
use syn::{parse_macro_input, Ident, LitStr, Token};

#[allow(clippy::upper_case_acronyms)]
type USHORT = u16;
#[allow(clippy::upper_case_acronyms)]
type PWCH = *mut u16;

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Copy, Clone)]
struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWCH,
}
// Define a custom input struct to hold both the variable name and the string literal
struct UnicodeStringInput {
    var_name: Ident,
    _eq: Token![=],
    value: LitStr,
}

impl Parse for UnicodeStringInput {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(UnicodeStringInput {
            var_name: input.parse()?,
            _eq: input.parse()?,
            value: input.parse()?,
        })
    }
}

#[proc_macro]
pub fn unicode_string(input: TokenStream) -> TokenStream {
    let UnicodeStringInput {
        var_name, value, ..
    } = parse_macro_input!(input as UnicodeStringInput);
    let content = value.value();
    let encoded: Vec<u16> = content.encode_utf16().chain(std::iter::once(0)).collect();
    let len = (encoded.len() - 1) * std::mem::size_of::<u16>(); // Length in bytes, excluding null terminator
    let max_len = encoded.len() * std::mem::size_of::<u16>();

    // Generate the static data and UNICODE_STRING initialization, including the variable definition
    let output = quote! {
        static mut #var_name: UNICODE_STRING = {
            static ENCODED: &[u16] = &[#(#encoded),*];
            UNICODE_STRING {
                Length: #len as u16,
                MaximumLength: #max_len as u16,
                Buffer: ENCODED.as_ptr() as *mut u16,
            }
        };
    };

    TokenStream::from(output)
}
