# Typed discovery точек расширения

Статус: accepted для первого delivery-среза #161.

## Назначение

`unica.project.discover` помогает исследовать 1С-проект до изменения кода. Это
не механизм авторизации, не замена code review и не разрешение на mutation.
Первый срез — только read-only `mode=explore`.

## Границы первого среза

Запрос содержит `task`, набор явно переданных `concepts`, необязательные
`searchTerms`, `knownArtifacts`, `sourceSet` и ресурсные `limits`.
`mode=explore` возвращает related artifacts, проверенные runtime flow edges,
actionable candidates и checks. Он never emits a receipt, не вызывает handler,
не меняет workspace и не добавляет скрытые domain-specific synonyms.

В первый срез не входят receipts, proposal validation, mutation guards,
lease/store, stale-mutation rejection и rollout deny/warn.

## Application pipeline

`DiscoverExtensionPointsUseCase` получает факты только через typed evidence
ports: metadata catalog, managed form inspection, BSL lexical search,
definition и call graph, а также support state. Infrastructure provider не
вызывает другой provider, не выбирает архитектуру и не делает вывод по
display-text parsing другого адаптера.

Каждая запись evidence обязана содержать canonical identity, source location,
provider name/version, coverage, freshness fingerprint снимка и стабильный
identifier evidence. Application слой строит evidence graph и ссылается на эти
identifiers во всех выводах.

Provider outcome имеет ровно одно состояние:

- `complete` — исчерпывающий результат в границах typed query;
- `bounded` — ответ ограничен установленным лимитом;
- `unavailable` — provider штатно недоступен;
- `failed` — provider завершился ошибкой;
- `contract_violation` — provider нарушил typed contract.

Только `complete` empty может быть отрицательным доказательством для ровно
того запроса, который был передан provider. `bounded`, `unavailable` и `failed`
никогда не являются отрицательным доказательством; `contract_violation`
останавливает promotion такого evidence в граф.

## Evidence graph и выводы

Отчёт разделяет:

1. related artifacts — связанные metadata objects, modules и формы;
2. runtime flow edges — типизированные `calls`, `handles`, `subscribes`;
3. actionable extension points — конкретные методы, handlers и bindings.

`contains` и `defines` — structural evidence. Structural связь, lexical match
или единственное определение не доказывают runtime flow и не создают actionable
candidate. Platform callback или form command становится flow только при
совместимом typed binding evidence от предназначенного provider.

Partial results и missing checks сериализуются отдельно от blocking errors.
Отчёт не содержит общий score/confidence: coverage, freshness, provider outcome
и evidence links выводятся независимо.

## Снимок и файловая безопасность

Перед исследованием selected source set захватывается как immutable manifest:
canonical contained relative paths в детерминированном порядке и SHA-256 raw
bytes каждого файла. BOM и EOL являются частью content fingerprint. Reads
bounded по числу файлов и байтам, проверяют containment, отклоняют escaping
symlink и обнаруживают замену файла между capture и verified read.

Platform-generated `ConfigDumpInfo.xml` с корнем `ConfigDumpInfo` не является
source evidence. Discovery не синтезирует platform `configVersion` и не читает
непроверенный live output индексатора как snapshot-grade fact.

## Публичный контракт

Единственный публичный сервер остаётся `unica`; public tool называется
`unica.project.discover`. В schema запрещены unknown fields, raw adapter args,
`proposals`, `discoveryReceipt`, `dryRun` и `confirm`. Параметры limits —
ресурсные пределы, а не показатели релевантности.

Результат помещается в `data.discovery` и детерминированно сортируется. Он
включает snapshot fingerprint, provider outcomes, artifacts, flow edges,
candidates и checks. В первом срезе поле receipt отсутствует.

## Последующие срезы

Proposal verdict (`supported`, `contradicted`, `unknown`), durable receipts и
mutation enforcement разрешены только отдельным ADR после точной спецификации
wire shape, snapshot state, lease lifecycle, resolver scope и post-mutation
reconciliation. Реализация из PR #117 — исследовательский материал, не источник
production кода.
