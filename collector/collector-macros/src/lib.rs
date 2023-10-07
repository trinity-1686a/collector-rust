mod parse_spec;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Attribute, DeriveInput, Lit, Meta, NestedMeta};

fn get_source(attrs: &[Attribute]) -> (String, String) {
    let meta = attrs[0].parse_meta().unwrap();
    if let Meta::List(metalist) = meta {
        assert_eq!(metalist.nested.len(), 1);
        if let NestedMeta::Meta(Meta::NameValue(meta_name_value)) = &metalist.nested[0] {
            if meta_name_value.path.is_ident("source") {
                if let Lit::Str(s) = &meta_name_value.lit {
                    if let Some((file, section)) = s.value().split_once('#') {
                        return (file.to_owned(), section.to_owned());
                    }
                }
            }
        }
    }
    panic!("invalid invocation")
}

#[proc_macro_derive(Descriptor, attributes(descriptor))]
pub fn derive_answer_fn(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let attrs: Vec<_> = input
        .attrs
        .into_iter()
        .filter(|attr| attr.path.is_ident("descriptor"))
        .collect();

    let (file, section) = get_source(&attrs);

    let section = parse_spec::extract_section(&file, &section).unwrap();

    let ident = input.ident;
    quote! {
        impl #ident {
          fn file() -> &'static str {
            #file
          }
          fn content() -> &'static str {
            #section
          }
        }
    }
    .into()
}
