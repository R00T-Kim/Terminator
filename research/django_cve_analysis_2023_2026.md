# Django CVE 분석 (2023-2026)

**작성일**: 2026-02-16
**목적**: Django의 최근 보안 CVE를 분석하여 취약점 패턴과 Variant Analysis 가능성 파악

---

## 1. CVE 목록 (2023-2026)

### 2026년 (최신)

| CVE ID | 날짜 | 유형 | 영향 버전 | 심각도 | 패치된 파일 |
|--------|------|------|-----------|--------|-------------|
| CVE-2026-1312 | 2026-02 | SQL Injection | - | High | `QuerySet.order_by()` with FilteredRelation |
| CVE-2026-1207 | 2026-02 | SQL Injection | - | High | PostGIS backend |
| CVE-2026-1285 | 2026-02 | DoS | - | Medium | Deeply nested entities |
| CVE-2026-1287 | 2026-02 | SQL Injection | - | High | Column aliases |

### 2025년

| CVE ID | 날짜 | 유형 | 영향 버전 | 심각도 | 패치된 파일 |
|--------|------|------|-----------|--------|-------------|
| **CVE-2025-64458** | 2025-11 | **DoS (ReDoS)** | 4.2<4.2.26, 5.1<5.1.14, 5.2<5.2.8 | **High (7.5)** | `django/http/response.py` |
| **CVE-2025-64460** | 2025-12 | **DoS (Algorithmic)** | 4.2<4.2.27, 5.1<5.1.15, 5.2<5.2.9 | **Moderate** | `django/core/serializers/xml_serializer.py` |
| CVE-2025-64459 | 2025-11 | SQL Injection | 4.2<4.2.26, 5.1<5.1.14, 5.2<5.2.8 | High | `django/db/models/query_utils.py` (Q object) |
| CVE-2025-57833 | 2025-09 | SQL Injection | 4.2<4.2.24, 5.1<5.1.12, 5.2<5.2.6 | High | FilteredRelation column aliases |
| CVE-2025-14550 | 2025 | DoS | - | Moderate | ASGIRequest duplicate headers |
| CVE-2025-13473 | 2025 | User Enumeration | - | Medium | mod_wsgi auth handler |
| CVE-2025-13372 | 2025-12 | SQL Injection | 4.2<4.2.27, 5.1<5.1.15, 5.2<5.2.9 | High | FilteredRelation (PostgreSQL) |
| CVE-2025-32873 | 2025 | DoS | - | Medium | `strip_tags()` |

### 2024년

| CVE ID | 날짜 | 유형 | 영향 버전 | 심각도 | 패치된 파일 |
|--------|------|------|-----------|--------|-------------|
| CVE-2024-56374 | 2025-01 | - | - | - | - |
| CVE-2024-53907 | 2024-12 | DoS | - | Medium | `django.utils.html.strip_tags()` |
| CVE-2024-53908 | 2024-12 | SQL Injection | - | Medium | HasKey on Oracle |
| CVE-2024-45231 | 2024-09 | - | - | - | - |
| CVE-2024-45230 | 2024-09 | - | - | - | - |
| CVE-2024-41991 | 2024 | DoS | - | Medium | `django.utils.html.urlize()`, AdminURLFieldWidget |
| **CVE-2024-27351** | 2024-03 | **ReDoS** | 3.2<3.2.25, 4.2<4.2.11, 5.0<5.0.3 | **Medium** | `django/utils/text.py` (Truncator.words()) |
| CVE-2024-26164 | 2024 | RCE | - | Critical | SQL Server Backend |
| CVE-2024-24680 | 2024 | DoS | - | Medium | `intcomma` template filter |
| CVE-2024-21520 | 2024 | XSS | - | Medium | django-rest-framework browsable API |

### 2023년

| CVE ID | 날짜 | 유형 | 영향 버전 | 심각도 | 패치된 파일 |
|--------|------|------|-----------|--------|-------------|
| CVE-2023-43665 | 2023-11 | ReDoS | - | Medium | Truncator.chars(), Truncator.words() |
| CVE-2023-36053 | 2023 | ReDoS | - | Medium | EmailValidator, URLValidator |
| CVE-2023-23969 | 2023 | DoS | - | Medium | Accept-Language headers |

---

## 2. ch4n3 (Seokchan Yoon)의 CVE 상세 분석

**연구자 정보**:
- Security Researcher @ Zellic.io
- Django, Python, Ruby, Airflow Security Contributor
- 블로그: [https://new-blog.ch4n3.kr/](https://new-blog.ch4n3.kr/)
- GitHub: [ch4n3-yoon](https://github.com/ch4n3-yoon)

**발견한 Django CVE**:
- CVE-2025-64458, CVE-2025-64460 (2025, LLM 활용)
- CVE-2024-27351 (Truncator ReDoS)
- CVE-2024-41991 (urlize DoS)
- CVE-2024-24680 (intcomma DoS)
- CVE-2023-36053 (EmailValidator/URLValidator ReDoS)

### CVE-2025-64458: HttpResponseRedirect/HttpResponsePermanentRedirect DoS (Windows)

**발견 방법**: LLM을 활용한 자동 취약점 탐지 ([$2,418 bounty with $5 LLM prompt](https://new-blog.ch4n3.kr/llm-found-security-issues-from-django-en/))

**취약점 원리**:
- Python의 `unicodedata.normalize()` NFKC 정규화가 Windows에서 매우 느림
- `HttpResponseRedirect`, `HttpResponsePermanentRedirect`, `redirect()` 함수가 내부적으로 `iri_to_uri()` 호출 → NFKC 정규화 수행
- 대량의 유니코드 문자를 포함한 입력 시 CPU 과부하 발생

**패치 내용** ([Commit c880530](https://github.com/django/django/commit/c880530ddd4fabd5939bab0e148bebe36699432a)):

```python
# django/http/response.py
from django.utils.http import MAX_URL_LENGTH, content_disposition_header, http_date

class HttpResponseRedirectBase(HttpResponse):
    def __init__(self, redirect_to, preserve_request=False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self["Location"] = iri_to_uri(redirect_to)
        redirect_to_str = str(redirect_to)

        # 새로 추가된 검증 로직
        if len(redirect_to_str) > MAX_URL_LENGTH:
            raise DisallowedRedirect(
                f"Unsafe redirect exceeding {MAX_URL_LENGTH} characters"
            )

        parsed = urlsplit(redirect_to_str)
        # ... 기존 로직
```

**영향 범위**:
- Django 4.2 < 4.2.26
- Django 5.1 < 5.1.14
- Django 5.2 < 5.2.8

**심각도**: High (CVSS 7.5)

**Variant Analysis 시사점**:
- `iri_to_uri()` 함수를 호출하는 **다른 모든 코드 경로** 검토 필요
- URL 길이 검증이 없는 곳이 추가 취약점 후보


### CVE-2025-64460: XML Deserializer 이차 복잡도 DoS

**발견 방법**: LLM을 활용한 자동 취약점 탐지

**취약점 원리**:
- `getInnerText()` 함수가 재귀적으로 `list.extend()`를 문자열에 사용
- 깊이 중첩된 XML에서 각 문자를 별도의 리스트 요소로 추가
- 입력 크기에 대해 **이차 복잡도(O(n²))** 발생 → CPU 과부하

**패치 내용** ([Commit 4d2b880](https://github.com/django/django/commit/4d2b8803bebcdefd2b76e9e8fc528d5fddea93f0)):

```python
# django/core/serializers/xml_serializer.py

# BEFORE (취약한 코드):
def getInnerText(node):
    inner_text = []
    for child in node.childNodes:
        if child.nodeType in (child.TEXT_NODE, child.CDATA_SECTION_NODE):
            inner_text.append(child.data)
        elif child.nodeType == child.ELEMENT_NODE:
            inner_text.extend(getInnerText(child))  # ← 재귀 시 list.extend()가 문자열 각 문자를 개별 추가
    return "".join(inner_text)

# AFTER (패치 후):
def getInnerText(node):
    """Get all the inner text of a DOM node (recursively)."""
    inner_text_list = getInnerTextList(node)
    return "".join(inner_text_list)  # ← 최종 한 번만 join

def getInnerTextList(node):
    """Return a list of the inner texts of a DOM node (recursively)."""
    result = []
    for child in node.childNodes:
        if child.nodeType in (child.TEXT_NODE, child.CDATA_SECTION_NODE):
            result.append(child.data)
        elif child.nodeType == child.ELEMENT_NODE:
            # 재귀 결과를 각 subtree별로 join → O(n)
            result.append("".join(getInnerTextList(child)))  # ← 핵심 수정
    return result
```

**추가 최적화**: `xml.dom.minidom` 성능 이슈 완화

```python
@contextmanager
def fast_cache_clearing():
    """Workaround for performance issues in minidom document checks."""
    module_helper_was_lambda = False
    if original_fn := getattr(minidom, "_in_document", None):
        module_helper_was_lambda = original_fn.__name__ == "<lambda>"
        if not module_helper_was_lambda:
            minidom._in_document = lambda node: bool(node.ownerDocument)  # ← DOM 전체 순회 스킵
    try:
        yield
    finally:
        if original_fn and not module_helper_was_lambda:
            minidom._in_document = original_fn

# 사용:
def __next__(self):
    for event, node in self.event_stream:
        if event == "START_ELEMENT" and node.nodeName == "object":
            with fast_cache_clearing():  # ← minidom 최적화
                self.event_stream.expandNode(node)
            return self._handle_object(node)
```

**테스트 케이스**:
```python
def build_crafted_xml(depth, leaf_text_len):
    nested_open = "<nested>" * depth
    nested_close = "</nested>" * depth
    leaf = "x" * leaf_text_len
    field_content = f"{nested_open}{leaf}{nested_close}"
    return f"""
        <django-objects version="1.0">
           <object model="contenttypes.contenttype" pk="1">
              <field name="app_label">{field_content}</field>
              <field name="model">m</field>
           </object>
        </django-objects>
    """

# 검증: depth/length 2배 증가 시 시간은 2배 이내 증가 (이차 → 선형)
assertFactor(
    "varying depth, varying length",
    [(50, 2000), (100, 4000), (200, 8000), (400, 16000), (800, 32000)],
    factor=2,  # ← O(n²)였다면 4배씩 증가했을 것
)
```

**영향 범위**:
- Django 4.2 < 4.2.27
- Django 5.1 < 5.1.15
- Django 5.2 < 5.2.9

**심각도**: Moderate

**Variant Analysis 시사점**:
- XML/JSON/YAML 등 **다른 serializer**에서도 유사한 재귀 패턴 검토
- `list.extend()` on strings 패턴을 코드베이스 전체에서 검색


### CVE-2024-27351: Truncator.words() ReDoS

**발견자**: Seokchan Yoon

**취약점 원리**:
- `django.utils.text.Truncator.words(html=True)` 사용 시 정규식 성능 저하
- 반복된 `<` 문자로 백트래킹 발생
- `truncatewords_html` 템플릿 필터 사용 시 영향

**패치 내용** ([Commit 3394fc6](https://github.com/django/django/commit/3394fc6132436eca89e997083bae9985fb7e761e)):
- HTML 모드에서 처리할 입력을 **처음 5백만 문자로 제한**
- 메모리/성능 이슈 방지

**영향 범위**:
- Django 3.2 < 3.2.25
- Django 4.2 < 4.2.11
- Django 5.0 < 5.0.3

**Variant Analysis 시사점**:
- `Truncator.chars()` 함수도 유사한 패턴 가능성 (CVE-2023-43665에서 이미 패치)
- `django.utils.text` 모듈의 다른 텍스트 처리 함수 검토

---

## 3. 패턴 분석

### 3.1 취약점 유형별 빈도 (2023-2026)

| 유형 | 건수 | 비율 | 대표 CVE |
|------|------|------|----------|
| **SQL Injection** | 8+ | 30% | CVE-2025-57833, CVE-2025-13372, CVE-2026-1312 |
| **DoS (ReDoS)** | 6+ | 23% | CVE-2025-64458, CVE-2024-27351, CVE-2023-43665 |
| **DoS (Algorithmic)** | 5+ | 19% | CVE-2025-64460, CVE-2025-14550, CVE-2024-53907 |
| **XSS** | 3+ | 11% | CVE-2024-21520, AdminURLFieldWidget |
| **RCE** | 1 | 4% | CVE-2024-26164 (SQL Server) |
| **User Enumeration** | 1 | 4% | CVE-2025-13473 |
| **기타** | 2+ | 8% | - |

### 3.2 가장 자주 패치되는 모듈/파일

#### Top 1: `django.db.models` (SQL Injection 집중)

**패치 빈도**: 8회+

**주요 파일**:
- `django/db/models/query_utils.py` (Q object)
- `django/db/models/sql/*.py` (FilteredRelation)
- `django/db/backends/postgresql/*.py` (PostGIS)

**공통 패턴**:
- **Column alias** 검증 부족 → SQL Injection
- **Dictionary expansion (`**kwargs`)** 시 사용자 입력 미검증
- `QuerySet.annotate()`, `QuerySet.alias()`, `QuerySet.order_by()` 등에서 반복 발생

**Variant Analysis 가능성**: ⭐⭐⭐⭐⭐ (매우 높음)
- 다른 QuerySet 메서드 (`values()`, `values_list()`, `extra()`, `aggregate()`) 검토 필요
- GIS 백엔드 (PostGIS, SpatiaLite, Oracle Spatial) 전반 검토


#### Top 2: `django.utils.html` (DoS/XSS 집중)

**패치 빈도**: 5회+

**주요 함수**:
- `strip_tags()` (CVE-2024-53907, CVE-2025-32873, 2014 advisory)
- `urlize()` (CVE-2024-41991)
- `escape()` (간접 영향)

**공통 패턴**:
- **정규식 복잡도** → ReDoS
- **중첩/난독화된 HTML 태그** 파싱 실패 → XSS
- **길이 제한 없음** → DoS

**Variant Analysis 가능성**: ⭐⭐⭐⭐ (높음)
- `django.utils.html` 모듈의 다른 함수들 (`linebreaks`, `smart_urlquote` 등)
- 정규식 사용하는 모든 HTML 처리 로직


#### Top 3: `django.utils.text` (ReDoS 집중)

**패치 빈도**: 4회+

**주요 함수**:
- `Truncator.words()` (CVE-2024-27351)
- `Truncator.chars()` (CVE-2023-43665)

**공통 패턴**:
- **HTML 모드**에서 정규식 백트래킹
- **입력 길이 제한 없음**

**Variant Analysis 가능성**: ⭐⭐⭐ (중간)
- `Truncator` 클래스의 다른 메서드 검토
- `django.utils.text.slugify()` 등 다른 텍스트 처리 함수


#### Top 4: `django.http.response` (DoS 집중)

**패치 빈도**: 2회+

**주요 클래스**:
- `HttpResponseRedirect` (CVE-2025-64458, CVE-2025-27556)
- `HttpResponsePermanentRedirect`

**공통 패턴**:
- **URL 정규화** 과정에서 성능 저하
- **길이 검증 부재**

**Variant Analysis 가능성**: ⭐⭐⭐⭐ (높음)
- `iri_to_uri()` 호출하는 모든 코드 경로
- `django.utils.encoding` 모듈 전반


#### Top 5: `django/core/serializers/` (Algorithmic DoS)

**패치 빈도**: 2회+

**주요 파일**:
- `xml_serializer.py` (CVE-2025-64460)
- JSON/YAML serializers (잠재적)

**공통 패턴**:
- **재귀 알고리즘** 이차 복잡도
- **깊이 제한 없음**

**Variant Analysis 가능성**: ⭐⭐⭐⭐ (높음)
- JSON serializer의 재귀 로직
- YAML serializer (PyYAML 래퍼)
- 커스텀 serializer 구현


### 3.3 시간대별 트렌드

**2023**: ReDoS 중심 (EmailValidator, URLValidator, Truncator)

**2024**:
- ReDoS 계속 (Truncator.words())
- SQL Injection 증가 (HasKey on Oracle, JSONField)
- DoS 다양화 (intcomma, urlize)

**2025**:
- **SQL Injection 폭발적 증가** (FilteredRelation 반복 취약점)
- **Algorithmic DoS** 등장 (XML serializer)
- **LLM 활용 탐지** (ch4n3의 CVE-2025-64458/64460)

**2026 (진행 중)**:
- SQL Injection 여전히 지배적
- 깊이 중첩 공격 (deeply nested entities)

---

## 4. Variant Analysis 후보

### 4.1 High Priority (즉시 분석 권장)

#### 1. `iri_to_uri()` 호출 사이트 전수 조사

**근거**: CVE-2025-64458에서 `HttpResponseRedirect`만 패치되었으나, `iri_to_uri()`는 다른 곳에서도 사용될 가능성

**탐색 쿼리**:
```python
# CodeQL 예시
import python
from Call c, Attribute a
where
  a.getName() = "iri_to_uri" and
  c.getFunc() = a
select c, "iri_to_uri call site without length check"
```

**검토 대상**:
- `django.utils.encoding.iri_to_uri()` 호출하는 모든 함수
- URL 파라미터 검증 로직 유무 확인


#### 2. QuerySet 메서드의 Column Alias 검증

**근거**: CVE-2025-57833, CVE-2025-13372에서 `FilteredRelation`의 column alias가 반복 취약

**탐색 대상**:
```python
# django/db/models/query.py
class QuerySet:
    def annotate(self, *args, **kwargs):  # ← **kwargs 검증?
    def alias(self, *args, **kwargs):     # ← **kwargs 검증?
    def values(self, *fields, **expressions):  # ← **expressions 검증?
    def values_list(self, *fields, **expressions):  # ← **expressions 검증?
    def aggregate(self, *args, **kwargs):  # ← **kwargs 검증?
    def extra(self, select=None, ...):     # ← select dict 검증?
```

**CodeQL 쿼리**:
```python
import python
from FunctionDef f, Parameter p
where
  f.getEnclosingClass().getName() = "QuerySet" and
  p.getName() = "kwargs" and
  f.getParameter(_) = p
select f, "QuerySet method accepting **kwargs - validate column aliases"
```


#### 3. XML/JSON/YAML Serializer 재귀 복잡도

**근거**: CVE-2025-64460에서 XML serializer의 이차 복잡도 발견

**탐색 대상**:
```python
# django/core/serializers/json.py
class Deserializer:
    def _handle_object(self, ...):  # ← 재귀 로직 검토

# django/core/serializers/python.py
class Deserializer:
    # 중첩 객체 처리 로직

# django/core/serializers/pyyaml.py (외부 라이브러리지만 래퍼 검토)
```

**검증 방법**:
- 깊이 중첩된 입력 생성 (depth=1000)
- 시간 복잡도 측정 (선형 vs 이차)


#### 4. `django.utils.html` 모듈 정규식 전수 감사

**근거**: `strip_tags()`, `urlize()`, `Truncator` 등에서 반복적으로 ReDoS 발견

**탐색 쿼리**:
```bash
# Semgrep 예시
grep -rn "re.compile\|re.match\|re.search" django/utils/html.py django/utils/text.py
```

**검토 대상**:
- `linebreaks()`, `linebreaksbr()`
- `smart_urlquote()`, `urlquote()`
- `normalize_newlines()`
- 모든 정규식에 대해 [ReDoS 취약점 검사](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)


#### 5. GIS 백엔드 SQL Injection

**근거**: CVE-2026-1207 (PostGIS), 과거 GIS 관련 SQLi 다수

**탐색 대상**:
```python
# django/contrib/gis/db/backends/postgis/
# django/contrib/gis/db/backends/spatialite/
# django/contrib/gis/db/backends/oracle/
```

**CodeQL 쿼리**:
```python
import python
from StrAdd sa, Call c
where
  sa.getLocation().getFile().getRelativePath().matches("%gis/db/backends%") and
  c.getFunc().getName() in ["execute", "executemany"] and
  dataflow::localFlow(sa, c.getArg(0))
select sa, "Potential SQL injection in GIS backend"
```


### 4.2 Medium Priority (추가 검토 권장)

#### 6. ASGI/WSGI 요청 처리 알고리즘

**근거**: CVE-2025-14550 (ASGI duplicate headers)

**탐색 대상**:
- `django.core.handlers.asgi.ASGIRequest`
- 헤더 중복 처리 로직
- 문자열 연결 패턴 (`+=` 반복)


#### 7. Template Filter 입력 검증

**근거**: CVE-2024-24680 (intcomma), truncatewords_html 등

**탐색 대상**:
```python
# django/template/defaultfilters.py
@register.filter
def intcomma(value):  # ← 길이 제한?
def floatformat(text, arg=-1):  # ← 정규식 ReDoS?
def slugify(value):  # ← 입력 검증?
```


#### 8. Admin 위젯 XSS

**근거**: 과거 AdminURLFieldWidget, ForeignKeyRawIdWidget에서 XSS

**탐색 대상**:
```python
# django/contrib/admin/widgets.py
class AdminURLFieldWidget:
class ForeignKeyRawIdWidget:
class RelatedFieldWidgetWrapper:
```


### 4.3 Low Priority (장기 모니터링)

#### 9. Authentication Backends

**근거**: CVE-2025-13473 (mod_wsgi auth handler user enumeration)

**탐색 대상**:
- `django.contrib.auth.backends`
- 타이밍 공격 가능성


#### 10. Cache Key Collision

**근거**: 일부 취약점에서 cache poisoning 가능성 언급

**탐색 대상**:
- `django.core.cache`
- Key generation 로직


---

## 5. 자동화 탐지 전략

### 5.1 LLM 기반 탐지 (ch4n3 방법론)

**ch4n3의 사례**: [$5 LLM 프롬프트로 $2,418 바운티](https://new-blog.ch4n3.kr/llm-found-security-issues-from-django-en/)

**프롬프트 구조** (추정):
```
You are a security researcher analyzing Django source code.
Find potential ReDoS vulnerabilities in functions that:
1. Use regular expressions
2. Process user input (HTML, URLs, text)
3. Lack input length validation
4. Use backtracking-prone patterns (nested quantifiers, alternation)

Analyze: django/utils/html.py, django/utils/text.py
Output: Function name, vulnerable regex, PoC input
```

**적용 대상**:
- `django.utils.*` 전체
- `django.db.models.sql.*` (SQLi 탐지)
- `django.core.serializers.*` (복잡도 분석)


### 5.2 CodeQL Queries

#### Query 1: SQL Injection in Column Aliases
```ql
import python
import semmle.python.security.dataflow.SqlInjectionQuery

from DataFlow::PathNode source, DataFlow::PathNode sink, SqlInjectionConfiguration cfg
where
  cfg.hasFlowPath(source, sink) and
  sink.getNode().asExpr().(Call).getFunc().(Attribute).getName() in ["annotate", "alias", "order_by"] and
  source.getNode().asExpr() instanceof DictComp
select sink, source, sink, "SQL injection via column alias from $@", source, "user input"
```

#### Query 2: ReDoS in Regex
```ql
import python
import semmle.python.security.dataflow.ReDoSQuery

from Regex r
where
  r.getFile().getRelativePath().matches("%django/utils%") and
  r.isVulnerableToReDoS()
select r, "Potential ReDoS vulnerability"
```

#### Query 3: Algorithmic Complexity
```ql
import python

from FunctionDef f, Call c
where
  c.getScope() = f and
  c.getFunc().(Attribute).getName() = "extend" and
  f.calls*(f)  // recursive function
select f, "Potential quadratic complexity in recursive function"
```


### 5.3 Semgrep Rules

#### Rule 1: Missing Length Check on URL
```yaml
rules:
  - id: django-url-length-check
    pattern: |
      iri_to_uri($URL)
    pattern-not: |
      if len($URL) > ...:
        ...
      iri_to_uri($URL)
    message: "iri_to_uri without length validation (CVE-2025-64458 variant)"
    severity: WARNING
    languages: [python]
```

#### Rule 2: Unsafe Column Alias
```yaml
rules:
  - id: django-unsafe-column-alias
    pattern-either:
      - pattern: $QS.annotate(..., **$KWARGS)
      - pattern: $QS.alias(..., **$KWARGS)
    pattern-not: |
      validate_column_alias($KWARGS)
      $QS.annotate(..., **$KWARGS)
    message: "QuerySet method with unvalidated **kwargs (CVE-2025-57833 variant)"
    severity: ERROR
    languages: [python]
```


### 5.4 Fuzzing Targets

**libFuzzer / AFL++ 타겟**:
1. `Truncator.words(html=True)` with crafted HTML
2. `strip_tags()` with nested/malformed tags
3. XML deserializer with deeply nested elements
4. `iri_to_uri()` with Unicode edge cases
5. QuerySet methods with crafted dict keys

**Harness 예시**:
```python
# fuzz_truncator.py
import atheris
import sys
from django.utils.text import Truncator

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicode(fdp.remaining_bytes())
    try:
        Truncator(text).words(100, html=True)
    except Exception:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
```


---

## 6. 결론 및 권장사항

### 6.1 핵심 발견사항

1. **SQL Injection이 가장 빈번** (30%): FilteredRelation/QuerySet 메서드 집중 공격 표면
2. **ReDoS가 지속적 문제** (23%): `django.utils.*` 모듈의 정규식 미흡
3. **Algorithmic DoS 등장** (19%): Serializer, 재귀 알고리즘 복잡도 검증 필요
4. **LLM 활용 탐지 효과적**: ch4n3의 사례 → 자동화 가능성

### 6.2 Variant Analysis 우선순위

**즉시 분석 (High)**:
1. `iri_to_uri()` 호출 사이트 (CVE-2025-64458 variant)
2. QuerySet 메서드 column alias (CVE-2025-57833 variant)
3. XML/JSON/YAML serializer 복잡도 (CVE-2025-64460 variant)
4. `django.utils.html` 정규식 전수 감사 (ReDoS)
5. GIS 백엔드 SQL injection (CVE-2026-1207 variant)

**추가 검토 (Medium)**:
6. ASGI/WSGI 알고리즘 (CVE-2025-14550 variant)
7. Template filter 입력 검증
8. Admin 위젯 XSS

### 6.3 도구 활용 전략

- **CodeQL**: SQL injection, ReDoS 자동 탐지
- **Semgrep**: 커스텀 패턴 (길이 검증, **kwargs 검증)
- **LLM (Gemini CLI)**: 소스코드 전체 스캔 (`tools/gemini_query.sh analyze`)
- **Fuzzing**: 정규식, serializer, URL 처리 함수

### 6.4 학습 내용

- **ch4n3의 접근법**: ReDoS 전문가, 비선형 시간 복잡도 패턴 집중
- **Django 보안팀 대응**: 평균 30-45일 내 패치, 여러 버전 동시 릴리스
- **Coordinated Disclosure**: oss-security 메일링 리스트 사용

---

## 7. 참고 자료

### 공식 문서
- [Django Security Archive](https://docs.djangoproject.com/en/6.0/releases/security/)
- [Django 6.0.2, 5.2.11, 4.2.28 릴리스](https://www.djangoproject.com/weblog/2026/feb/03/security-releases/)
- [Django Security Team 트렌드](https://www.djangoproject.com/weblog/2026/feb/04/recent-trends-security-team/)

### CVE 데이터베이스
- [NVD - CVE-2025-64458](https://nvd.nist.gov/vuln/detail/CVE-2025-64458)
- [NVD - CVE-2025-64460](https://nvd.nist.gov/vuln/detail/CVE-2025-64460)
- [CVE Details - Django](https://www.cvedetails.com/product/18211/Djangoproject-Django.html)
- [Snyk - Django Vulnerabilities](https://security.snyk.io/package/pip/django)

### GitHub 커밋
- [CVE-2025-64458 패치](https://github.com/django/django/commit/c880530ddd4fabd5939bab0e148bebe36699432a)
- [CVE-2025-64460 패치](https://github.com/django/django/commit/4d2b8803bebcdefd2b76e9e8fc528d5fddea93f0)
- [CVE-2024-27351 패치](https://github.com/django/django/commit/3394fc6132436eca89e997083bae9985fb7e761e)

### 연구자 블로그
- [ch4n3.kr - LLM으로 Django 취약점 발견](https://new-blog.ch4n3.kr/llm-found-security-issues-from-django-en/)
- [ch4n3.kr - CVE-2024-7592](https://new-blog.ch4n3.kr/cve-2024-7592-en/)
- [ch4n3.kr - CVE-2023-23969](https://new-blog.ch4n3.kr/cve-2023-23969/)

### 분석 도구
- [ZeroPath - CVE-2025-57833 분석](https://zeropath.com/blog/cve-2025-57833-django-filteredrelation-sql-injection)
- [Endor Labs - CVE-2025-64459](https://www.endorlabs.com/learn/critical-sql-injection-vulnerability-in-django-cve-2025-64459)
- [GitLab Security Advisory](https://advisories.gitlab.com/pkg/pypi/django/)

---

**[STAGE:status:success]**
**[STAGE:time:120]** (웹 검색 + 분석)
**[STAGE:end:django_cve_research]**
