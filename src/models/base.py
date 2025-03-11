from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.orm import declarative_base

Base = declarative_base()

apply_message_type = ENUM("inner", "declarative",
                          name="apply_message_type",
                          metadata=Base.metadata)
apply_task_priority = ENUM("on_fire", "urgent", "high", "medium", "low",
                           name="apply_task_priority",
                           metadata=Base.metadata)
