# ADR-0005: Yerleşik küçük politika değerlendiricisi

Durum: kabul edildi

## Karar
Ürünün **erişim politikası** (sınıf × profil tavanı × ortam × bağlam etiketi → allow/ask/deny) küçük, yerleşik, deklaratif bir değerlendiriciyle yapılır (`policy.yaml`, deny-kazanır). Arayüz Cedar/OPA ile değiştirilebilir kalır ama v1'de entegre edilmez (D12). Hedef sistemlerin politikası (Kyverno, OPA, bulut) ayrı kavramdır; ürün onları yalnız okur.
