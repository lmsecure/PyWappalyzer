from pydantic import Field

from .base import APISchema


class Group(APISchema):
    id: str = "N/A"
    name: str


class Category(APISchema):
    id: str = "N/A"
    name: str
    groups: list[int] = Field(default_factory=list)
    priority: int = 0