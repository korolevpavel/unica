---
name: role-edit
description: Точечно изменить одно право существующей роли 1С, не пересоздавая остальные права, RLS и шаблоны
argument-hint: <RightsPath> <ObjectName> <RightName> <true|false>
allowed-tools:
  - Bash
  - Read
---

# /role-edit — точечное редактирование права роли

## MCP routing

- Используй MCP `unica` и инструмент `unica.role.edit`; не редактируй
  `Rights.xml` вручную и не вызывай внутренние адаптеры.
- По умолчанию выполняется предпросмотр. Передай `dryRun: false` только когда
  пользователь прямо подтвердил изменение.
- После применения `unica.role.edit` проверяет итоговую структуру XML; для
  расширенной диагностики вызови `unica.role.validate`.

## Вызов

```json
{
  "cwd": "<workspace>",
  "RightsPath": "src/Roles/ДемоРедактирование/Ext/Rights.xml",
  "ObjectName": "Catalog.Демо",
  "Name": "Delete",
  "Value": false,
  "dryRun": false
}
```

Вызов изменяет или добавляет только `Delete` у `Catalog.Демо`. Остальные права,
RLS-ограничения, шаблоны и глобальные флаги сохраняются. Повторный вызов с теми
же значениями ничего не меняет.
