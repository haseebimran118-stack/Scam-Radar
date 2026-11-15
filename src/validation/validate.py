from datetime import datetime
from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    field_validator
)


class URLhausRecord(BaseModel):
    url: str = Field(min_length=1)
    host: str = Field(min_length=1)
    url_status: str = "unknown"
    threat: str = "unknown"
    tags: list[str] = Field(default_factory=list)
    date_added: datetime | None = None

    @field_validator("url", "host")
    @classmethod
    def clean_text(cls, value):
        value = value.strip()

        if not value:
            raise ValueError("Value cannot be empty")

        return value

    @field_validator("url_status")
    @classmethod
    def check_status(cls, value):
        value = value.lower().strip()

        if value not in ["online", "offline", "unknown"]:
            raise ValueError(
                "Status must be online, offline or unknown"
            )

        return value

    @field_validator("threat", mode="before")
    @classmethod
    def clean_threat(cls, value):
        return value or "unknown"

    @field_validator("tags", mode="before")
    @classmethod
    def clean_tags(cls, value):
        if value is None:
            return []

        if not isinstance(value, list):
            raise ValueError("Tags must be a list")

        return value

    @field_validator("date_added", mode="before")
    @classmethod
    def parse_date_added(cls, value):
        if value is None or value == "":
            return None

        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            value = value.strip()

            if value.endswith(" UTC"):
                value = value[:-4] + "+00:00"

            return datetime.fromisoformat(value)

        return value


def validate_records(records: list):
    valid_records = []
    rejected_records = []

    for record in records:
        try:
            validated = URLhausRecord.model_validate(record)

            valid_records.append(
                validated.model_dump(mode="json")
            )

        except ValidationError as error:
            rejected_records.append({
                "record": record,
                "reason": str(error)
            })

    return valid_records, rejected_records