# ADR-0006: Kubernetes adapter'ı kendi asgari HTTPS istemcisini kullanır

Durum: kabul edildi (WP5)

## Bağlam
Tasarım §6.6 `@kubernetes/client-node`'u aday olarak anmıştı (**doğrulanacak**). Adapter'ın güvenlik gereksinimleri istemcinin davranışına doğrudan bağlıdır: kimlik yalnız pinli uç noktaya gitmeli, TLS doğrulaması kapatılamamalı, yönlendirme izlenmemeli, ortam proxy'si/kubeconfig'i devreye girmemeli ve mutasyon fiilleri yapısal olarak bulunmamalı.

## Karar
`packages/adapters/kubernetes` yalnız Node çekirdeği (`node:https`) üzerinde ~150 satırlık bir istemci (`K8sClient`) kullanır:
- yalnız `GET`; `POST` yalnız iki inceleme yoluna (`selfsubjectreviews`, `selfsubjectrulesreviews`, WP6); başka yola istek yapılamaz;
- yalnız https, `rejectUnauthorized: true`, yalnız kimlikteki CA güvenilir; kimlik göndermeden ÖNCE sunucu URL'si ve CA parmak izi profil pini ile karşılaştırılır (`assertPinned`);
- yönlendirme reddedilir; yanıt boyutu ve süre sınırlı; `AbortSignal` bağlı;
- `Secret` türü `as=Table` biçiminde okunur: değerler sunucudan hiç çekilmez.

## Sonuçlar
- (+) Tedarik zinciri yüzeyi küçük (yeni bağımlılık yok), davranış testle kilitli.
- (+) İstemci tarafında mutasyon yapılamaz; yeni fiil = kod değişikliği + conformance.
- (−) Watch, exec, port-forward, çoklu auth sağlayıcı yok (v1 kapsamı dışında; exec kimlik eklentileri broker katmanında WP6).
- (−) API keşfi yok: okunabilir türler kapalı bir tablodur (`kinds.ts`); CRD okuma (Kyverno PolicyReport vb.) Faz 1'de tabloya açıkça eklenir.
- Gerekirse sonradan `@kubernetes/client-node` bir `K8sClient` uygulaması olarak takılabilir; adapter yalnız bu arayüze bağlıdır.
