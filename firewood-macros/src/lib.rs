// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.

//! Proc macros for Firewood.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{ItemFn, ReturnType, parse_macro_input};

/// Arguments for the `#[metrics]` attribute: a single identifier naming a counter constant in
/// `crate::registry`. The corresponding histogram constant must also exist in `crate::registry`
/// under the name `{IDENT}_DURATION_SECONDS`.
struct MetricsArgs {
    ident: syn::Ident,
}

impl Parse for MetricsArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let ident: syn::Ident = input.parse().map_err(|e| {
            syn::Error::new(
                e.span(),
                "expected a registry constant identifier, e.g., #[metrics(MY_OPERATION)]",
            )
        })?;
        if !input.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "unexpected argument; only one identifier is accepted \
                 — the description is declared in the registry doc comment",
            ));
        }
        Ok(MetricsArgs { ident })
    }
}

/// A proc macro attribute that automatically adds metrics instrumentation to functions.
///
/// Wraps a `Result`-returning function with:
/// - A counter `crate::registry::{IDENT}` labeled with `success = "true"` or `"false"`
/// - A histogram `crate::registry::{IDENT}_DURATION_SECONDS` recording the elapsed duration
///
/// Both constants must be declared in `crate::registry` via `firewood_metrics::define_metrics!`;
/// the compiler validates they exist.
///
/// # Usage
/// ```rust,ignore
/// use firewood_macros::metrics;
///
/// // Registry must declare PROPOSAL_COMMITS and PROPOSAL_COMMITS_DURATION_SECONDS
/// #[metrics(PROPOSAL_COMMITS)]
/// fn commit(...) -> Result<(), Error> {
///     // function body
/// }
/// ```
///
/// # Requirements
/// - The function must return a `Result<T, E>` type
/// - `crate::registry::{IDENT}` (counter) and `crate::registry::{IDENT}_DURATION_SECONDS`
///   (histogram) must both be declared in the calling crate's `registry` module
/// - The `metrics` crate must be available in the calling crate
#[proc_macro_attribute]
pub fn metrics(args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);

    if args.is_empty() {
        return syn::Error::new_spanned(
            &input_fn,
            "expected a registry constant identifier, e.g., #[metrics(MY_OPERATION)]",
        )
        .to_compile_error()
        .into();
    }

    let parsed_args = match syn::parse::<MetricsArgs>(args) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };

    // Validate that the function returns a Result
    let return_type = match &input_fn.sig.output {
        ReturnType::Type(_, ty) => ty,
        ReturnType::Default => {
            return syn::Error::new_spanned(
                &input_fn.sig,
                "Function must return a Result<T, E> to use #[metrics] attribute",
            )
            .to_compile_error()
            .into();
        }
    };

    let is_result = match return_type.as_ref() {
        syn::Type::Path(type_path) => type_path
            .path
            .segments
            .last()
            .is_some_and(|seg| seg.ident == "Result"),
        _ => false,
    };

    if !is_result {
        return syn::Error::new_spanned(
            return_type,
            "Function must return a Result<T, E> to use #[metrics] attribute",
        )
        .to_compile_error()
        .into();
    }

    let expanded = generate_metrics_wrapper(&input_fn, &parsed_args.ident);
    TokenStream::from(expanded)
}

fn generate_metrics_wrapper(input_fn: &ItemFn, ident: &syn::Ident) -> proc_macro2::TokenStream {
    let fn_vis = &input_fn.vis;
    let fn_sig = &input_fn.sig;
    let fn_block = &input_fn.block;
    let fn_attrs = &input_fn.attrs;

    // Histogram constant: {IDENT}_DURATION_SECONDS — must be declared in crate::registry
    let duration_ident = format_ident!("{}_DURATION_SECONDS", ident);

    quote! {
        #(#fn_attrs)*
        #fn_vis #fn_sig {
            let __metrics_start = ::std::time::Instant::now();

            let __metrics_result = { #fn_block };

            // Use static label arrays to avoid runtime allocation
            static __METRICS_LABELS_SUCCESS: &[(&str, &str)] = &[("success", "true")];
            static __METRICS_LABELS_ERROR: &[(&str, &str)] = &[("success", "false")];
            let __metrics_labels = if __metrics_result.is_err() {
                __METRICS_LABELS_ERROR
            } else {
                __METRICS_LABELS_SUCCESS
            };

            ::firewood_metrics::firewood_counter!(#ident, __metrics_labels).increment(1);
            ::firewood_metrics::firewood_histogram!(#duration_ident).record(__metrics_start.elapsed().as_secs_f64());

            __metrics_result
        }
    }
}

/// Hash modes a test runs under, parsed from `#[hash_mode(...)]` arguments.
struct HashModeArgs {
    eth: bool,
    merkledb: bool,
}

impl Parse for HashModeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let idents = Punctuated::<syn::Ident, syn::Token![,]>::parse_terminated(input)?;
        if idents.is_empty() {
            return Err(syn::Error::new(
                input.span(),
                "expected at least one hash mode, e.g. #[hash_mode(eth)] or #[hash_mode(eth, merkledb)]",
            ));
        }
        let mut args = HashModeArgs {
            eth: false,
            merkledb: false,
        };
        for ident in &idents {
            let slot = match ident.to_string().as_str() {
                "eth" => &mut args.eth,
                "merkledb" => &mut args.merkledb,
                other => {
                    return Err(syn::Error::new_spanned(
                        ident,
                        format!("unknown hash mode `{other}`; expected `eth` or `merkledb`"),
                    ));
                }
            };
            if *slot {
                return Err(syn::Error::new_spanned(
                    ident,
                    format!("duplicate hash mode `{ident}`"),
                ));
            }
            *slot = true;
        }
        Ok(args)
    }
}

/// Annotates a test (or any item) with the hash configuration(s) it runs under.
///
/// Today this expands to the equivalent compile-time gate, so behavior is
/// identical to a hand-written `#[cfg]`:
///
/// - `#[hash_mode(eth)]`           → `#[cfg(feature = "ethhash")]`
/// - `#[hash_mode(merkledb)]`      → `#[cfg(not(feature = "ethhash"))]`
/// - `#[hash_mode(eth, merkledb)]` → no gate (compiled in both)
///
/// It exists so that, once the `ethhash` feature is removed (issue #1088),
/// these annotations can be re-wired to select the hash mode at runtime and run
/// the full suite under every mode in a single binary — without revisiting each
/// test's gate by hand.
///
/// Place it above `#[test]`:
///
/// ```rust,ignore
/// use firewood_macros::hash_mode;
///
/// #[hash_mode(eth)]
/// #[test]
/// fn only_under_ethhash() { /* ... */ }
/// ```
#[proc_macro_attribute]
pub fn hash_mode(args: TokenStream, input: TokenStream) -> TokenStream {
    let parsed = match syn::parse::<HashModeArgs>(args) {
        Ok(a) => a,
        Err(e) => return e.to_compile_error().into(),
    };
    let gate = hash_mode_gate(&parsed);
    let item: proc_macro2::TokenStream = input.into();
    quote! {
        #gate
        #item
    }
    .into()
}

/// Maps the declared hash modes to the compile-time gate they currently expand
/// to. Factored out so it can be unit-tested without a `proc_macro` context.
fn hash_mode_gate(args: &HashModeArgs) -> proc_macro2::TokenStream {
    if args.eth && args.merkledb {
        // Runs under both modes: no gate.
        quote! {}
    } else if args.eth {
        quote! { #[cfg(feature = "ethhash")] }
    } else {
        // merkledb only — parsing guarantees at least one mode is set.
        quote! { #[cfg(not(feature = "ethhash"))] }
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_slow_proc_macro_compilation() {
        // Test that the proc macro generates compilable code
        let t = trybuild::TestCases::new();
        t.pass("tests/compile_pass/*.rs");
        t.compile_fail("tests/compile_fail/*.rs");
    }

    #[test]
    fn test_metrics_args_parsing() {
        // Test identifier parsing
        let input = quote::quote! { TEST_METRIC };
        let parsed: MetricsArgs = syn::parse2(input).unwrap();
        assert_eq!(parsed.ident.to_string(), "TEST_METRIC");
    }

    #[test]
    fn test_invalid_args_parsing() {
        // A literal number is not a valid identifier
        let input = quote::quote! { 123 };
        let result: syn::Result<MetricsArgs> = syn::parse2(input);
        assert!(result.is_err());

        // Extra arguments after the ident are not allowed
        let input = quote::quote! { MY_IDENT, extra };
        let result: syn::Result<MetricsArgs> = syn::parse2(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_generated_code_structure() {
        // Test that the proc macro generates the expected code structure
        use syn::{ItemFn, parse_quote};

        let input: ItemFn = parse_quote! {
            fn test_function() -> Result<(), &'static str> {
                Ok(())
            }
        };

        let ident: syn::Ident = syn::parse_str("TEST_METRIC").unwrap();
        let result = generate_metrics_wrapper(&input, &ident);
        let generated_code = result.to_string();

        // Verify key components are present in the generated code
        assert!(generated_code.contains("__METRICS_LABELS_SUCCESS"));
        assert!(generated_code.contains("__METRICS_LABELS_ERROR"));
        assert!(generated_code.contains("TEST_METRIC"));
        assert!(generated_code.contains("TEST_METRIC_DURATION_SECONDS"));
        assert!(
            generated_code.contains("std")
                && generated_code.contains("Instant")
                && generated_code.contains("now")
        );
        assert!(generated_code.contains("counter"));
        assert!(generated_code.contains("histogram"));
    }

    #[test]
    fn test_hash_mode_args_parsing() {
        let eth: HashModeArgs = syn::parse2(quote::quote! { eth }).unwrap();
        assert!(eth.eth && !eth.merkledb);

        let merkledb: HashModeArgs = syn::parse2(quote::quote! { merkledb }).unwrap();
        assert!(!merkledb.eth && merkledb.merkledb);

        let both: HashModeArgs = syn::parse2(quote::quote! { eth, merkledb }).unwrap();
        assert!(both.eth && both.merkledb);
    }

    #[test]
    fn test_hash_mode_invalid_args() {
        // empty list
        assert!(syn::parse2::<HashModeArgs>(quote::quote! {}).is_err());
        // unknown mode
        assert!(syn::parse2::<HashModeArgs>(quote::quote! { sha256 }).is_err());
        // duplicate mode
        assert!(syn::parse2::<HashModeArgs>(quote::quote! { eth, eth }).is_err());
    }

    #[test]
    fn test_hash_mode_gate_tokens() {
        let eth_gate = hash_mode_gate(&HashModeArgs {
            eth: true,
            merkledb: false,
        });
        assert_eq!(
            eth_gate.to_string(),
            quote::quote! { #[cfg(feature = "ethhash")] }.to_string()
        );

        let merkledb_gate = hash_mode_gate(&HashModeArgs {
            eth: false,
            merkledb: true,
        });
        assert_eq!(
            merkledb_gate.to_string(),
            quote::quote! { #[cfg(not(feature = "ethhash"))] }.to_string()
        );

        // both modes => no gate
        let both_gate = hash_mode_gate(&HashModeArgs {
            eth: true,
            merkledb: true,
        });
        assert!(both_gate.to_string().is_empty());
    }
}
