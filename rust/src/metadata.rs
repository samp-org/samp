use parity_scale_codec::{Compact, Decode, Error as CodecError, Input};
use std::collections::HashMap;

const METADATA_MAGIC: u32 = 0x6174_656d;

#[derive(Debug, Clone)]
pub enum Error {
    Scale(String),
    UnknownTypeDef(u8),
    UnknownStorageEntryType(u8),
    UnknownPrimitive(u8),
    InvalidOptionTag(u8),
    NonSequential {
        got: u32,
        expected: u32,
    },
    TypeIdMissing(u32),
    Shape {
        ctx: &'static str,
        kind: &'static str,
    },
    VariableWidth(u32),
    StorageNotFound {
        pallet: String,
        entry: String,
    },
    FieldNotFound {
        field: String,
    },
    AccountInfoShort {
        need: usize,
        got: usize,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Scale(s) => write!(f, "scale decode: {s}"),
            Self::UnknownTypeDef(t) => write!(f, "unknown TypeDef tag {t}"),
            Self::UnknownStorageEntryType(t) => write!(f, "unknown StorageEntryType tag {t}"),
            Self::UnknownPrimitive(t) => write!(f, "unknown primitive tag {t}"),
            Self::InvalidOptionTag(t) => write!(f, "invalid Option tag {t}"),
            Self::NonSequential { got, expected } => {
                write!(f, "non-sequential type id {got} (expected {expected})")
            }
            Self::TypeIdMissing(id) => write!(f, "type id {id} missing from registry"),
            Self::Shape { ctx, kind } => write!(f, "{ctx} is not a {kind}"),
            Self::VariableWidth(id) => write!(f, "type id {id} has variable width"),
            Self::StorageNotFound { pallet, entry } => {
                write!(f, "storage entry not found: {pallet}.{entry}")
            }
            Self::FieldNotFound { field } => write!(f, "field not found: {field}"),
            Self::AccountInfoShort { need, got } => {
                write!(f, "storage value too short: need {need} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug)]
pub struct Metadata {
    registry: Vec<TypeShape>,
    storage: HashMap<(String, String), u32>,
    calls: HashMap<(String, String), (u8, u8)>,
    errors: ErrorTable,
}

#[derive(Clone, Debug)]
pub struct StorageLayout {
    pub offset: usize,
    pub width: usize,
}

#[derive(Clone, Debug, Default)]
pub struct ErrorTable {
    by_idx: HashMap<(u8, u8), ErrorEntry>,
}

#[derive(Clone, Debug)]
pub struct ErrorEntry {
    pub pallet: String,
    pub variant: String,
    pub doc: String,
}

impl Metadata {
    pub fn from_runtime_metadata(bytes: &[u8]) -> Result<Self, Error> {
        let input = &mut &bytes[..];

        let magic = u32::decode(input).map_err(scale)?;
        if magic != METADATA_MAGIC {
            return Err(Error::Scale(format!(
                "metadata magic mismatch: 0x{magic:08x}"
            )));
        }
        let version = u8::decode(input).map_err(scale)?;
        if version != 14 {
            return Err(Error::Scale(format!(
                "metadata version {version} unsupported (need V14)"
            )));
        }

        let registry = read_registry(input)?;
        let walked = walk_pallets(input)?;
        let errors = ErrorTable::build(&registry, &walked.errors);
        let calls = resolve_call_indices(&registry, &walked.pending_calls);

        Ok(Self {
            registry,
            storage: walked.storage,
            calls,
            errors,
        })
    }

    pub fn storage_layout(
        &self,
        pallet: &str,
        entry: &str,
        field_path: &[&str],
    ) -> Result<StorageLayout, Error> {
        let value_ty = self
            .storage
            .get(&(pallet.to_string(), entry.to_string()))
            .copied()
            .ok_or_else(|| Error::StorageNotFound {
                pallet: pallet.to_string(),
                entry: entry.to_string(),
            })?;

        let mut offset = 0usize;
        let mut current = value_ty;
        for field_name in field_path {
            let fields = type_at(&self.registry, current)?.composite("path traversal")?;
            let mut found = None;
            for (name, ty) in fields {
                if name == field_name {
                    found = Some(*ty);
                    break;
                }
                offset += byte_size(&self.registry, *ty)?;
            }
            current = found.ok_or_else(|| Error::FieldNotFound {
                field: (*field_name).to_string(),
            })?;
        }

        let width = type_at(&self.registry, current)?.unsigned_int_width("storage_layout")?;
        Ok(StorageLayout { offset, width })
    }

    pub fn find_call_index(&self, pallet: &str, call: &str) -> Option<(u8, u8)> {
        self.calls
            .get(&(pallet.to_string(), call.to_string()))
            .copied()
    }

    pub fn errors(&self) -> &ErrorTable {
        &self.errors
    }
}

impl StorageLayout {
    pub fn decode_uint(&self, data: &[u8]) -> Result<u128, Error> {
        let end = self.offset + self.width;
        if data.len() < end {
            return Err(Error::AccountInfoShort {
                need: end,
                got: data.len(),
            });
        }
        let mut buf = [0u8; 16];
        buf[..self.width].copy_from_slice(&data[self.offset..end]);
        Ok(u128::from_le_bytes(buf))
    }
}

impl ErrorTable {
    pub fn humanize(&self, pallet_idx: u8, err_idx: u8) -> Option<String> {
        let e = self.by_idx.get(&(pallet_idx, err_idx))?;
        if e.doc.is_empty() {
            Some(format!("{}::{}", e.pallet, e.variant))
        } else {
            Some(format!("{}::{}: {}", e.pallet, e.variant, e.doc))
        }
    }

    pub fn humanize_rpc_error(&self, raw: &str) -> String {
        if let Some(payload) = find_after_any(raw, &["RPC error: ", "transaction failed: "]) {
            if let Some(json_str) = trim_to_json(payload) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if let Some(s) = v.get("data").and_then(|d| d.as_str()) {
                        return self
                            .maybe_translate_module(s)
                            .unwrap_or_else(|| s.to_string());
                    }
                    if let Some(s) = v.get("message").and_then(|m| m.as_str()) {
                        return s.to_string();
                    }
                }
            }
        }
        if let Some(t) = self.maybe_translate_module(raw) {
            return t;
        }
        raw.to_string()
    }

    fn maybe_translate_module(&self, s: &str) -> Option<String> {
        let start = s.find("Module")?;
        let tail = &s[start..];
        let idx = u8::try_from(parse_after(tail, "index:")?).ok()?;
        let err = u8::try_from(parse_first_byte_after(tail, "error:")?).ok()?;
        self.humanize(idx, err)
    }

    fn build(registry: &[TypeShape], pallets: &[PalletErrorRef]) -> Self {
        let mut by_idx = HashMap::new();
        for p in pallets {
            if let Some(TypeShape::Variant(variants)) = usize::try_from(p.error_ty)
                .ok()
                .and_then(|i| registry.get(i))
            {
                for (variant_idx, variant_name, doc) in variants {
                    by_idx.insert(
                        (p.pallet_idx, *variant_idx),
                        ErrorEntry {
                            pallet: p.pallet_name.clone(),
                            variant: variant_name.clone(),
                            doc: doc.clone(),
                        },
                    );
                }
            }
        }
        Self { by_idx }
    }
}

fn find_after_any<'a>(s: &'a str, needles: &[&str]) -> Option<&'a str> {
    needles
        .iter()
        .find_map(|n| s.find(n).map(|i| &s[i + n.len()..]))
}

fn trim_to_json(s: &str) -> Option<&str> {
    let start = s.find('{')?;
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if esc {
            esc = false;
            continue;
        }
        match b {
            b'\\' if in_str => esc = true,
            b'"' => in_str = !in_str,
            b'{' if !in_str => depth += 1,
            b'}' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[start..=i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_after(haystack: &str, needle: &str) -> Option<u32> {
    let after = haystack.find(needle)?;
    let rest = &haystack[after + needle.len()..];
    let digits: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn parse_first_byte_after(haystack: &str, needle: &str) -> Option<u32> {
    let after = haystack.find(needle)?;
    let rest = &haystack[after + needle.len()..];
    let bracket = rest.find('[')?;
    let inside = &rest[bracket + 1..];
    let digits: String = inside.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

#[derive(Clone, Debug)]
enum TypeShape {
    Primitive { width: usize, unsigned_int: bool },
    Composite(Vec<(String, u32)>),
    Array { len: u32, inner: u32 },
    Tuple(Vec<u32>),
    Variant(Vec<(u8, String, String)>),
    Variable,
}

#[derive(Clone, Debug)]
struct PalletErrorRef {
    pallet_name: String,
    pallet_idx: u8,
    error_ty: u32,
}

#[derive(Clone, Debug)]
struct PendingCalls {
    pallet_name: String,
    pallet_idx: u8,
    calls_ty: u32,
}

#[derive(Debug, Default)]
struct PalletWalkResult {
    storage: HashMap<(String, String), u32>,
    pending_calls: Vec<PendingCalls>,
    errors: Vec<PalletErrorRef>,
}

impl TypeShape {
    fn composite(&self, ctx: &'static str) -> Result<&[(String, u32)], Error> {
        match self {
            Self::Composite(fields) => Ok(fields),
            _ => Err(Error::Shape {
                ctx,
                kind: "composite",
            }),
        }
    }

    fn unsigned_int_width(&self, ctx: &'static str) -> Result<usize, Error> {
        match self {
            Self::Primitive {
                width,
                unsigned_int: true,
            } => Ok(*width),
            _ => Err(Error::Shape {
                ctx,
                kind: "unsigned integer primitive",
            }),
        }
    }

    fn variant_entries(&self) -> Option<&[(u8, String, String)]> {
        match self {
            Self::Variant(v) => Some(v),
            _ => None,
        }
    }
}

fn type_at(registry: &[TypeShape], id: u32) -> Result<&TypeShape, Error> {
    let idx = usize::try_from(id).map_err(|_| Error::TypeIdMissing(id))?;
    registry.get(idx).ok_or(Error::TypeIdMissing(id))
}

fn byte_size(registry: &[TypeShape], id: u32) -> Result<usize, Error> {
    match type_at(registry, id)? {
        TypeShape::Primitive { width, .. } => Ok(*width),
        TypeShape::Composite(fields) => fields
            .iter()
            .try_fold(0, |sum, (_, t)| Ok(sum + byte_size(registry, *t)?)),
        TypeShape::Array { len, inner } => {
            let len_usize = usize::try_from(*len).map_err(|_| Error::TypeIdMissing(*len))?;
            Ok(len_usize * byte_size(registry, *inner)?)
        }
        TypeShape::Tuple(ids) => ids
            .iter()
            .try_fold(0, |sum, t| Ok(sum + byte_size(registry, *t)?)),
        TypeShape::Variant(_) | TypeShape::Variable => Err(Error::VariableWidth(id)),
    }
}

fn read_registry<I: Input>(input: &mut I) -> Result<Vec<TypeShape>, Error> {
    let n = compact(input)?;
    let mut registry = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
    for expected in 0..n {
        let id = compact(input)?;
        if id != expected {
            return Err(Error::NonSequential { got: id, expected });
        }
        skip_strings(input)?;
        skip_type_params(input)?;
        registry.push(read_type_def(input)?);
        skip_strings(input)?;
    }
    Ok(registry)
}

fn read_type_def<I: Input>(input: &mut I) -> Result<TypeShape, Error> {
    Ok(match u8::decode(input).map_err(scale)? {
        0 => TypeShape::Composite(read_fields(input)?),
        1 => {
            let n = compact(input)?;
            let mut variants = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
            for _ in 0..n {
                let name = String::decode(input).map_err(scale)?;
                let _ = read_fields(input)?;
                let index = u8::decode(input).map_err(scale)?;
                let docs = <Vec<String>>::decode(input).map_err(scale)?;
                let doc = docs
                    .into_iter()
                    .map(|d| d.trim().to_string())
                    .find(|d| !d.is_empty())
                    .unwrap_or_default();
                variants.push((index, name, doc));
            }
            TypeShape::Variant(variants)
        }
        2 => {
            compact(input)?;
            TypeShape::Variable
        }
        3 => TypeShape::Array {
            len: u32::decode(input).map_err(scale)?,
            inner: compact(input)?,
        },
        4 => {
            let n = compact(input)?;
            let mut ids = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
            for _ in 0..n {
                ids.push(compact(input)?);
            }
            TypeShape::Tuple(ids)
        }
        5 => primitive_shape(u8::decode(input).map_err(scale)?)?,
        6 => {
            compact(input)?;
            TypeShape::Variable
        }
        7 => {
            compact(input)?;
            compact(input)?;
            TypeShape::Variable
        }
        tag => return Err(Error::UnknownTypeDef(tag)),
    })
}

fn read_fields<I: Input>(input: &mut I) -> Result<Vec<(String, u32)>, Error> {
    let n = compact(input)?;
    let mut fields = Vec::with_capacity(usize::try_from(n).unwrap_or(0));
    for _ in 0..n {
        let name = <Option<String>>::decode(input)
            .map_err(scale)?
            .unwrap_or_default();
        let ty = compact(input)?;
        let _ = <Option<String>>::decode(input).map_err(scale)?;
        skip_strings(input)?;
        fields.push((name, ty));
    }
    Ok(fields)
}

fn skip_type_params<I: Input>(input: &mut I) -> Result<(), Error> {
    for _ in 0..compact(input)? {
        let _ = String::decode(input).map_err(scale)?;
        match u8::decode(input).map_err(scale)? {
            0 => {}
            1 => {
                compact(input)?;
            }
            tag => return Err(Error::InvalidOptionTag(tag)),
        }
    }
    Ok(())
}

fn primitive_shape(tag: u8) -> Result<TypeShape, Error> {
    let (width, unsigned_int) = match tag {
        0 => (1, false),
        1 => (4, false),
        2 => return Ok(TypeShape::Variable),
        3 => (1, true),
        4 => (2, true),
        5 => (4, true),
        6 => (8, true),
        7 => (16, true),
        8 => (32, true),
        9 => (1, false),
        10 => (2, false),
        11 => (4, false),
        12 => (8, false),
        13 => (16, false),
        14 => (32, false),
        _ => return Err(Error::UnknownPrimitive(tag)),
    };
    Ok(TypeShape::Primitive {
        width,
        unsigned_int,
    })
}

fn walk_pallets<I: Input>(input: &mut I) -> Result<PalletWalkResult, Error> {
    let mut storage = HashMap::new();
    let mut pending_calls = Vec::new();
    let mut errors: Vec<PalletErrorRef> = Vec::new();

    for _ in 0..compact(input)? {
        let pallet_name = String::decode(input).map_err(scale)?;

        if option_tag(input)? {
            let _ = String::decode(input).map_err(scale)?;
            for _ in 0..compact(input)? {
                let entry_name = String::decode(input).map_err(scale)?;
                let _ = u8::decode(input).map_err(scale)?;
                let value_ty = read_storage_entry_value_type(input)?;
                storage.insert((pallet_name.clone(), entry_name), value_ty);
                let _ = <Vec<u8>>::decode(input).map_err(scale)?;
                skip_strings(input)?;
            }
        }

        let calls_ty = if option_tag(input)? {
            Some(compact(input)?)
        } else {
            None
        };

        skip_optional_compact(input)?;

        for _ in 0..compact(input)? {
            let _ = String::decode(input).map_err(scale)?;
            compact(input)?;
            let _ = <Vec<u8>>::decode(input).map_err(scale)?;
            skip_strings(input)?;
        }

        let error_ty = if option_tag(input)? {
            Some(compact(input)?)
        } else {
            None
        };

        let pallet_index = u8::decode(input).map_err(scale)?;

        if let Some(ty) = calls_ty {
            pending_calls.push(PendingCalls {
                pallet_name: pallet_name.clone(),
                pallet_idx: pallet_index,
                calls_ty: ty,
            });
        }

        if let Some(ty) = error_ty {
            errors.push(PalletErrorRef {
                pallet_name: pallet_name.clone(),
                pallet_idx: pallet_index,
                error_ty: ty,
            });
        }
    }

    Ok(PalletWalkResult {
        storage,
        pending_calls,
        errors,
    })
}

fn resolve_call_indices(
    registry: &[TypeShape],
    pending: &[PendingCalls],
) -> HashMap<(String, String), (u8, u8)> {
    let mut out = HashMap::new();
    for p in pending {
        let Ok(ty) = type_at(registry, p.calls_ty) else {
            continue;
        };
        let Some(variants) = ty.variant_entries() else {
            continue;
        };
        for (call_idx, call_name, _doc) in variants {
            out.insert(
                (p.pallet_name.clone(), call_name.clone()),
                (p.pallet_idx, *call_idx),
            );
        }
    }
    out
}

fn read_storage_entry_value_type<I: Input>(input: &mut I) -> Result<u32, Error> {
    match u8::decode(input).map_err(scale)? {
        0 => compact(input),
        1 => {
            for _ in 0..compact(input)? {
                let _ = u8::decode(input).map_err(scale)?;
            }
            compact(input)?;
            compact(input)
        }
        tag => Err(Error::UnknownStorageEntryType(tag)),
    }
}

fn compact<I: Input>(input: &mut I) -> Result<u32, Error> {
    Ok(<Compact<u32>>::decode(input).map_err(scale)?.0)
}

fn skip_strings<I: Input>(input: &mut I) -> Result<(), Error> {
    let _ = <Vec<String>>::decode(input).map_err(scale)?;
    Ok(())
}

fn option_tag<I: Input>(input: &mut I) -> Result<bool, Error> {
    match u8::decode(input).map_err(scale)? {
        0 => Ok(false),
        1 => Ok(true),
        tag => Err(Error::InvalidOptionTag(tag)),
    }
}

fn skip_optional_compact<I: Input>(input: &mut I) -> Result<(), Error> {
    if option_tag(input)? {
        compact(input)?;
    }
    Ok(())
}

fn scale(e: CodecError) -> Error {
    Error::Scale(e.to_string())
}
