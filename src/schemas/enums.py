from enum import StrEnum


class EnumMessageType(StrEnum):
    inner = "inner"
    declarative = "declarative"


class EnumTaskPriority(StrEnum):
    on_fire = "on_fire"
    urgent = "urgent"
    high = "high"
    medium = "medium"
    low = "low"
