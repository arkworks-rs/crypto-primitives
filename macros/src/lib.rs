extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

#[proc_macro_derive(Absorb)]
pub fn derive_absorb(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let absorb_impl = match input.data {
        Data::Struct(data_struct) => {
            match data_struct.fields {
                Fields::Named(ref fields) => {
                    let absorb_fields = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        quote! {
                            Absorb::to_sponge_bytes(&self.#name, dest);
                        }
                    });

                    let absorb_fields_elements = fields.named.iter().map(|f| {
                        let name = &f.ident;
                        quote! {
                            Absorb::to_sponge_field_elements(&self.#name, dest);
                        }
                    });

                    quote! {
                        impl #impl_generics Absorb for #name #ty_generics #where_clause {
                            fn to_sponge_bytes(&self, dest: &mut Vec<u8>) {
                                #( #absorb_fields )*
                            }

                            fn to_sponge_field_elements<F: PrimeField>(&self, dest: &mut Vec<F>) {
                                #( #absorb_fields_elements )*
                            }
                        }
                    }
                }
                // Handle other field types (Unnamed, Unit) if necessary...
                _ => panic!("Absorb only supports named fields"),
            }
        }
        // Handle other data types (Enum, Union) if necessary...
        _ => panic!("DeriveAbsorb only supports structs"),
    };

    TokenStream::from(absorb_impl)
}
