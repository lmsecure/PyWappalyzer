import itertools

from .schemas.detection import Detection
from .schemas.fingerprints import Fingerprint
from .schemas.taxonomy import Category, Group
from .schemas.patterns import Pattern


class Handler:
    def __init__(self, fingerprints: dict[str, Fingerprint], categories: dict[str, Category], groups: dict[str, Group]):
        self.fingerprints = fingerprints
        self.categories = categories
        self.groups = groups
        self.type_priority = {
            "js": 0,
            "meta": 1,
            "dom": 2,
            "headers": 3,
            "cookies": 3,
            "script_src": 4,
            "scripts": 5,
            "url": 5,
            "implied": 6,
        }

    def resolve_implies(self, detections: list[Detection]) -> list[Detection]:
        result = list(detections)
        detected_ids = {d.fingerprint.id for d in detections}

        for detection in detections:
            for implied_name in detection.fingerprint.implies:
                name = implied_name.split("\\;")[0]
                if name in detected_ids:
                    continue
                fingerprint = self.fingerprints.get(name)
                if fingerprint:
                    result.append(Detection.model_construct(
                        url=detection.url,
                        source_url="",
                        fingerprint=fingerprint,
                        app_type="implied",
                        pattern=Pattern(string=name),
                        value="",
                        key="",
                        resolved_version="",
                        via=detection.fingerprint.id, 
                        categories=None,
                        groups=None,
                    ))
                    detected_ids.add(name)

        return result

    def filter_by_requires(self, detections: list[Detection]) -> list[Detection]:
        filtered: list[Detection] = []

        detection_ids = {detection.fingerprint.id for detection in detections}
        for detection in detections:
            if not detection.fingerprint.requires:
                filtered.append(detection)
                continue

            if any(require in detection_ids for require in detection.fingerprint.requires):
                filtered.append(detection)

        return filtered

    def filter_by_requires_category(self, detections: list[Detection]) -> list[Detection]:
        filtered: list[Detection] = []

        categories = set(
            itertools.chain.from_iterable(
                detection.fingerprint.cats for detection in detections
            )
        )
        for detection in detections:
            if not detection.fingerprint.requires_category:
                filtered.append(detection)
                continue

            if any(
                require in categories for require in detection.fingerprint.requires_category
            ):
                filtered.append(detection)

        return filtered

    def filter_by_excludes(self, detections: list[Detection]) -> list[Detection]:
        # confidence по числу детектов на технологию
        confidence: dict[str, int] = {}
        for d in detections:
            confidence[d.fingerprint.id] = confidence.get(d.fingerprint.id, 0) + 1

        excludes: dict[str, str] = {}  # кого исключить → кто исключает
        for d in detections:
            for excluded in d.fingerprint.excludes:
                excludes[excluded] = d.fingerprint.id

        result = []
        for d in detections:
            tech_id = d.fingerprint.id
            if tech_id not in excludes:
                result.append(d)
                continue

            # кто нас исключает
            excluded_by = excludes[tech_id]
            # оставляем если у нас confidence выше
            if confidence.get(tech_id, 0) > confidence.get(excluded_by, 0):
                result.append(d)

        return result

    def set_categories(self, detections: list[Detection]) -> list[Detection]:
        if not self.categories:
            return detections

        for detection in detections:
            memo: dict[str, Category] = {}

            for category_id in detection.fingerprint.cats:
                category = self.categories.get(str(category_id))
                if category:
                    memo[category.id] = category

            if any(memo):
                detection.categories = list(memo.values())

        return detections


    def set_groups(self, detections: list[Detection]) -> list[Detection]:
        if not self.groups:
            return detections

        for detection in detections:
            memo: dict[str, Group] = {}

            if not detection.categories:
                continue

            for category in detection.categories:
                for group_id in category.groups:
                    group = self.groups.get(str(group_id))
                    if group:
                        memo[group.id] = group

            if any(memo):
                detection.groups = list(memo.values())

        return detections

    def build_detection_chains(self, detections: list[Detection]) -> list[Detection]:
        # script_src детекты: URL скрипта → имя технологии
        script_url_to_tech: dict[str, str] = {
            d.value: d.fingerprint.id
            for d in detections
            if d.app_type == "script_src"
        }

        for d in detections:
            if d.via:
                # via уже проставлен (например, implied) — не перезаписываем
                continue

            if d.source_url and d.source_url != d.url:
                owner = script_url_to_tech.get(d.source_url)
                if owner:
                    d.via = owner

        return detections
    
    def deduplicate(self, detections: list[Detection]) -> list[Detection]:
        
        best: dict[str, Detection] = {}

        for d in detections:
            name = d.fingerprint.id

            if name not in best:
                best[name] = d
                continue

            current = best[name]
            current_priority = self.type_priority.get(current.app_type, 99)
            new_priority = self.type_priority.get(d.app_type, 99)

            # случай 1: версии не было, появилась
            if d.resolved_version and not current.resolved_version:
                current.resolved_version = d.resolved_version
                current.app_type = d.app_type

            # случай 2: конфликт версий — побеждает более приоритетный источник
            elif d.resolved_version and current.resolved_version:
                if new_priority < current_priority:
                    current.resolved_version = d.resolved_version
                    current.app_type = d.app_type

        return list(best.values())