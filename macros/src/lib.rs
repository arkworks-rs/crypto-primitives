extern crate proc_macro;
use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Index};

#[proc_macro_derive(Absorb)]
pub fn derive_absorb(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let len = if let Data::Struct(ref data_struct) = input.data {
        data_struct.fields.len()
    } else {
        panic!(
            "`Absorb` can only be derived for structs, {} is not a struct",
            name
        );
    };

    let mut to_sponge_bytes = Vec::<TokenStream2>::with_capacity(len);
    let mut to_sponge_field_elements = Vec::<TokenStream2>::with_capacity(len);

    match input.data {
        Data::Struct(ref data_struct) => match data_struct.fields {
            Fields::Named(ref fields) => {
                let _: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| {
                        let name = &f.ident;
                        to_sponge_bytes.push(quote! {
                            Absorb::to_sponge_bytes(&self.#name, dest);
                        });
                    })
                    .collect();

                let _: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| {
                        let name = &f.ident;
                        to_sponge_field_elements.push(quote! {
                            Absorb::to_sponge_field_elements(&self.#name, dest);
                        });
                    })
                    .collect();
            }
            Fields::Unnamed(ref fields) => {
                let _: Vec<_> = fields
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        let index = Index::from(i);
                        to_sponge_bytes.push(quote! {
                            Absorb::to_sponge_bytes(&self.#index, dest);
                        });
                    })
                    .collect();

                let _: Vec<_> = fields
                    .unnamed
                    .iter()
                    .enumerate()
                    .map(|(i, _)| {
                        let index = Index::from(i);
                        to_sponge_field_elements.push(quote! {
                            Absorb::to_sponge_field_elements(&self.#index, dest);
                        });
                    })
                    .collect();
            }
            _ => panic!("Absorb only supports named and unnamed fields"),
        },
        // this should be unreachable, we already checked
        _ => panic!("Absorb only supports structs"),
    }

    quote! {
        impl #impl_generics Absorb for #name #ty_generics #where_clause {
            fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
                #( #to_sponge_bytes )*
            }

            fn to_sponge_field_elements<FieldType: PrimeField>(&self, dest: &mut Vec<FieldType>) {
                #( #to_sponge_field_elements )*
            }
        }
    }
    .into()
}
