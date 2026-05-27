//! PDF rendering via `printpdf` — header + tabla + footer + crypto block.
//!
//! Layout deliberately simple (AC-EXPORT-3 + D11 SPEC): pure Helvetica,
//! tabla con filas alternadas, última página con HMAC chain root + end.

use crate::audit::export::bundle::{BRAND_DEFAULT, ExportBundle};
use crate::error::{KvendraError, KvendraResult};
use printpdf::{BuiltinFont, Mm, PdfDocument, PdfDocumentReference, PdfLayerIndex, PdfPageIndex};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BrandConfig {
    pub legal_name: String,
    pub email: String,
}

impl Default for BrandConfig {
    fn default() -> Self {
        Self {
            legal_name: BRAND_DEFAULT.legal_name.to_string(),
            email: BRAND_DEFAULT.email.to_string(),
        }
    }
}

pub fn write_pdf(path: &Path, bundle: &ExportBundle, brand: &BrandConfig) -> KvendraResult<()> {
    let (doc, page1, layer1) =
        PdfDocument::new("Kvendra Audit Export", Mm(210.0), Mm(297.0), "Layer1");
    let helvetica = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| KvendraError::Audit(format!("pdf font: {e}")))?;
    let helvetica_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| KvendraError::Audit(format!("pdf font: {e}")))?;

    // Page 1: header + first table rows
    let layer = doc.get_page(page1).get_layer(layer1);

    // Header
    layer.use_text(
        "Kvendra — Audit Export",
        18.0,
        Mm(15.0),
        Mm(280.0),
        &helvetica_bold,
    );
    layer.use_text(
        format!("Exported by: {}", brand.legal_name),
        10.0,
        Mm(15.0),
        Mm(272.0),
        &helvetica,
    );
    if !brand.email.is_empty() {
        layer.use_text(
            format!("Contact: {}", brand.email),
            10.0,
            Mm(15.0),
            Mm(266.0),
            &helvetica,
        );
    }
    layer.use_text(
        format!("Generated at: {}", bundle.exported_at),
        10.0,
        Mm(15.0),
        Mm(260.0),
        &helvetica,
    );
    layer.use_text(
        format!("Total events: {}", bundle.events.len()),
        10.0,
        Mm(15.0),
        Mm(254.0),
        &helvetica,
    );

    // Column header
    layer.use_text(
        "TIMESTAMP                  PRIMITIVE/OP                 PROFILE      RESULT  SEV",
        8.0,
        Mm(15.0),
        Mm(245.0),
        &helvetica_bold,
    );

    let mut y = Mm(238.0);
    let mut current_page = page1;
    let mut current_layer = layer1;
    let mut page_num = 1u32;
    let mut page_count = 1u32;
    for ev in &bundle.events {
        if y.0 < 25.0 {
            // New page
            let (np, nl) = doc.add_page(Mm(210.0), Mm(297.0), "Layer");
            // Write footer of previous page
            draw_footer(&doc, current_page, current_layer, &helvetica, page_num);
            current_page = np;
            current_layer = nl;
            page_num += 1;
            page_count += 1;
            y = Mm(280.0);
        }
        let layer = doc.get_page(current_page).get_layer(current_layer);
        let row = format!(
            "{:25}  {:30}  {:10}  {:6}  {}",
            truncate(&ev.timestamp_iso8601, 25),
            truncate(&format!("{}:{}", ev.primitive, ev.action), 30),
            truncate(&ev.profile_id, 10),
            truncate(&ev.result_status, 6),
            truncate(&ev.severity, 4),
        );
        layer.use_text(row, 7.0, Mm(15.0), y, &helvetica);
        y = Mm(y.0 - 5.0);
    }

    // Crypto block on last page
    if y.0 < 60.0 {
        let (np, nl) = doc.add_page(Mm(210.0), Mm(297.0), "Layer");
        draw_footer(&doc, current_page, current_layer, &helvetica, page_num);
        current_page = np;
        current_layer = nl;
        page_num += 1;
        page_count += 1;
        y = Mm(280.0);
    }
    let layer = doc.get_page(current_page).get_layer(current_layer);
    y = Mm(y.0 - 15.0);
    layer.use_text("Cryptographic block", 12.0, Mm(15.0), y, &helvetica_bold);
    y = Mm(y.0 - 7.0);
    layer.use_text(
        format!(
            "Chain root HMAC: {}",
            truncate(&bundle.chain_root_hmac_hex, 80)
        ),
        7.0,
        Mm(15.0),
        y,
        &helvetica,
    );
    y = Mm(y.0 - 5.0);
    layer.use_text(
        format!(
            "Chain end  HMAC: {}",
            truncate(&bundle.chain_end_hmac_hex, 80)
        ),
        7.0,
        Mm(15.0),
        y,
        &helvetica,
    );
    y = Mm(y.0 - 5.0);
    layer.use_text(
        format!(
            "Chain key seed: {}",
            truncate(&bundle.chain_key_seed_hex, 80)
        ),
        7.0,
        Mm(15.0),
        y,
        &helvetica,
    );
    y = Mm(y.0 - 8.0);
    layer.use_text(
        format!("Verify online: {}", bundle.verifier_url),
        9.0,
        Mm(15.0),
        y,
        &helvetica_bold,
    );
    y = Mm(y.0 - 5.0);
    layer.use_text(
        "Or run: `kvendra audit verify <this-file>.json`",
        8.0,
        Mm(15.0),
        y,
        &helvetica,
    );

    // Footer last page
    draw_footer(&doc, current_page, current_layer, &helvetica, page_num);

    let bytes = doc
        .save_to_bytes()
        .map_err(|e| KvendraError::Audit(format!("pdf save: {e}")))?;
    std::fs::write(path, bytes)?;
    let _ = page_count; // currently unused — could be embedded as total
    Ok(())
}

fn draw_footer(
    doc: &PdfDocumentReference,
    page: PdfPageIndex,
    layer: PdfLayerIndex,
    font: &printpdf::IndirectFontRef,
    page_num: u32,
) {
    let l = doc.get_page(page).get_layer(layer);
    l.use_text(
        format!(
            "Page {}  ·  Verify: https://app.kvendra.cloud/audit-verify",
            page_num
        ),
        8.0,
        Mm(15.0),
        Mm(10.0),
        font,
    );
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}
