# ADR-0010: Typed project discovery

- Status: accepted
- Date: 2026-07-20

## Context

До mutation агенту нужны проверяемые факты о механизме 1С, а не совпадение по
имени metadata object или BSL method. Исследовательский PR #83 подтвердил
ценность discovery, но смешивал artifacts, runtime flow и extension points.

## Decision

Первый delivery-срез вводит один read-only public tool
`unica.project.discover` с `mode=explore`. Он получает typed evidence через
application ports, строит evidence graph и возвращает related artifacts,
runtime flow и actionable candidates с provenance. structural evidence не
доказывает runtime flow.

Все filesystem facts привязаны к bounded immutable source snapshot. Provider
outcomes сохраняют coverage и freshness; неполные и недоступные проверки видны
как checks, а не маскируются эвристикой. Infrastructure не делает
display-text parsing результатов другого adapter.

Этот срез never emits a receipt и не имеет mutation guards. Receipt storage,
lease, validate mode и enforcement будут отдельными решениями после фиксации
их безопасности и wire contract.

## Consequences

- Публичным остаётся один MCP server `unica` и только `unica.*` tool names.
- Ядро не содержит domain-specific synonyms и не назначает общий score.
- Без binding evidence ответ консервативно возвращает related artifact/check,
  а не утверждает runtime flow.
- Mutating tools продолжают работать по существующему contract до отдельного
  принятого решения о discovery guard.
