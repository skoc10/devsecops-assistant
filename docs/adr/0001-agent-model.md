# ADR-0001: Tek orkestratör + yüklenebilir skill

Durum: kabul edildi (tasarım r2)

## Bağlam
Alan başına ajan (kubernetes, database, pipelines, ...) ile tek orkestratör + skill modeli karşılaştırıldı (docs/design/03-agent-model.md §4.1). Gereksinim: ajanların kendi kubeconfig/DB parolasını saklaması kabul edilmez; token tüketimi asgari tutulur.

## Karar
Tek orkestratör ve Agent Skills (`SKILL.md`) kullanılır. Skill yetki taşımaz; araç setini yalnız talep eder, karar PEP'tedir. Ham serbest metni araçsız, kimliksiz bir **karantina özetleyici** okur. Alan ajanına geçiş koşulları §4.3'te yazılıdır.

## Sonuçlar
- Tek denetim izi, tek kanıt defteri, tek kararlı istem öneki (önbellek dostu).
- Skill başına araç seti tembel bağlanır (token ekonomisi, §4.5).
- Etkin araç sayısı sürekli ~40'ı aşarsa model yeniden değerlendirilir.
