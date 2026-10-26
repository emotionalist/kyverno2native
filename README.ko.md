# kyverno2native

[Kyverno](https://kyverno.io) 정책을 쿠버네티스 내장 어드미션 정책인
`ValidatingAdmissionPolicy`(VAP)와 `MutatingAdmissionPolicy`(MAP)로 변환합니다.

```bash
python3 kyverno2native.py my-policy.yaml
```

*[English README](README.md)*

---

## 왜 만들었나

쿠버네티스에서 사용자 정의 어드미션 정책은 그동안 주로 **어드미션 웹훅**으로 시행해 왔습니다.
API 서버가 매 요청마다 외부 정책 엔진에 동기적으로 HTTP 호출을 보내는 방식입니다. 요청마다
네트워크 왕복이 생기고, 엔진을 항상 켜 두어야 하며, 클러스터 가용성이 그 엔진에 묶입니다.
웹훅 호출이 실패하면 정책을 우회시키거나 정상 요청까지 막아야 합니다.

VAP(1.30 정식)와 MAP(1.36 정식)이 나오면서, API 서버가 CEL 표현식을 **자기 안에서** 평가할 수
있게 되었습니다. 웹훅도, 네트워크 홉도, 따로 띄워 둘 컴포넌트도 없습니다.

그래서 이런 질문이 생깁니다. **지금 웹훅으로 시행 중인 정책 가운데 얼마나 많은 것이 그냥
네이티브 정책이 될 수 있는가?**

Kyverno에는 ClusterPolicy로부터 VAP를 만들어 주는 `autogen` 기능이 있습니다. Kyverno 정책
라이브러리에서 네이티브 표현이 가능한 540개를 대상으로, 옵트인을 설정할 수 있는 곳에는 모두
설정하고 측정했습니다. **113개가 변환되었습니다.** 나머지 427개는 설정 누락이 아니었습니다.

- **기존 문법 정책 245개**(`pattern` / `anyPattern` / `deny` / `foreach`)는 옵트인을 넣을 자리가
  없습니다. 옵트인은 `validate.cel` 블록 안에 있는데, 한 규칙에 둘을 같이 쓰면 Kyverno 자신의
  웹훅이 거부합니다 — `only one of pattern, anyPattern, deny, foreach, cel can be specified`.
  옵트인하려면 규칙을 CEL로 먼저 다시 써야 하는데, 그게 바로 변환입니다.
- **CEL 기반 정책 타입 162개**(`ValidatingPolicy`, `MutatingPolicy`)에는 옵트인 필드 자체가
  없습니다.
- autogen은 **단일 규칙 정책만** 처리하고, 요청자의 역할을 참조하는 정책은 거부합니다.
- 쿠버네티스 1.36에서 **MAP 생성은 쓸 수 없습니다.**
  `--generateMutatingAdmissionPolicy=true`를 켜면 Kyverno 어드미션 컨트롤러가
  CrashLoopBackOff에 빠집니다. MAP이 `v1`으로 정식 기능인데도 제거된 alpha/beta API만
  탐지하기 때문입니다.

이 도구는 autogen이 다루지 못하는 범위를 담당합니다.

## 무엇을 하는가

| 입력 | 담당 | 출력 |
|---|---|---|
| `validate.cel`을 쓰는 `ClusterPolicy` | 구조 변환기 | VAP + 바인딩 |
| `ValidatingPolicy`, `MutatingPolicy` (CEL CRD) | 구조 변환기 | VAP / MAP + 바인딩 |
| 기존 문법 `ClusterPolicy` | **컴파일러** | VAP / MAP + 바인딩 |

두 경로는 작업 성격이 다릅니다. CEL 기반 정책은 이미 CEL로 쓰여 있어서, 실제 일은 껍데기를
다시 짜는 것입니다(`matchConstraints`, GVR 매핑, 이름 생성, 바인딩). 반면 기존 문법 정책은
CEL에 대응물이 없습니다. 패턴 트리와 앵커, JMESPath 조건을 불리언 CEL 식으로 **컴파일**해야
합니다.

두 경로 모두 Kyverno의 **파드 컨트롤러 autogen**을 재현합니다. 파드에 대한 규칙이
Deployment / StatefulSet / DaemonSet / ReplicaSet / ReplicationController / Job(`-ag1`)과
CronJob(`-ag2`)에도 적용되도록 정책 객체를 함께 생성합니다.

### 컴파일러가 구현한 패턴 의미론

| Kyverno | CEL |
|---|---|
| 평문 키 | 경로가 존재하고 **또한** 일치해야 함 |
| `=(key)` | 있으면 검사, 없으면 통과 |
| `X(key)` | 값이 없으면 `!has(key)`. 값이 있으면 `!has(key) \|\| !(값 일치)` — 즉 없거나 값이 다르면 통과 |
| `(key)` | 조건부 앵커 → 함의식 `!(조건) \|\| (본문)`의 전제로 모음 |
| `^(key)` | 리스트 원소 중 하나 이상 만족 |
| 와일드카드 맵 키 | 존재 검사(`.exists()`). `.all()`은 매치가 없을 때 공허참이 되어 통과시킴 |
| 패턴 아래의 리스트 | 리스트 전체에 `.all()` (패턴 쪽 원소는 1개만 허용) |
| `deny.conditions` | 부정해서 `validations` 식으로. deny는 존재 한정, validations는 전칭 |
| `patchStrategicMerge`의 스칼라·맵 필드 | `ApplyConfiguration` |

변이 경로는 검증 경로와 앵커 허용 목록이 다릅니다. `psm_to_apply`는 평문 키와 `+(key)`만
받고 나머지 앵커는 전부 거부합니다.

### 이 버전에 구현되지 않은 것

| Kyverno | 상태 |
|---|---|
| `+(key)` | "없을 때만"이라는 검사가 `matchCondition`으로 올라가므로 **패치 전체**를 게이트합니다. 한 패치에 `+()`가 둘 이상이면 해당 필드가 *모두* 없을 때만 변이가 적용됩니다. |
| `<(key)` | 거부 — `ConvertError: anchor < unsupported`. `matchConditions`로 올리는 처리는 없습니다. |
| `>(key)` | 앵커 정규식에는 들어 있으나 처리 분기가 없어 같은 방식으로 거부됩니다. |
| `patchStrategicMerge`에 리스트가 있는 경우 | 종류를 가리지 않고 거부 — `ConvertError: PSM list merge`. 컴파일러는 `ApplyConfiguration`만 생성하며 `JSONPatch`를 만들지 않습니다. (산출물의 `JSONPatch`는 원본 `MutatingPolicy`가 이미 쓰던 것이 그대로 복사된 것입니다.) |
| 수치 범위·수량 패턴 값(`32000-33000`, `>1Gi`) | 비교 정규식 `^(>=\|<=\|>\|<)\s*(-?\d+(?:\.\d+)?)$`에 걸리지 않고 **거부되지도 않아** 문자열 등호 비교로 떨어집니다. 범위·변이 패턴은 산출물을 확인하세요. |

## 설치

Python 3.8 이상과 PyYAML만 있으면 됩니다.

```bash
git clone https://github.com/emotionalist/kyverno2native
cd kyverno2native
pip install -r requirements.txt
```

## 사용법

```bash
# 정책 하나를 표준출력으로
python3 kyverno2native.py policy.yaml

# 디렉터리 전체를, 정책당 파일 하나씩
python3 kyverno2native.py -r ./policies -o ./out

# 정책별 결과 리포트까지
python3 kyverno2native.py -r ./policies -o ./out --report report.csv
```

```
위치 인자:
  inputs                Kyverno 정책 YAML 파일

옵션:
  -r, --recursive DIR   DIR 아래의 모든 *.yaml 정책을 변환
  -o, --outdir DIR      정책당 파일 하나씩 여기에 기록 (기본: 표준출력)
  --report CSV          정책별 결과 CSV 기록
  -q, --quiet           요약 출력 생략
```

변환하지 못하는 정책은 사유와 함께 보고하고 건너뜁니다. 나머지는 그대로 변환됩니다.

### 예시

```yaml
# 입력
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-ro-rootfs
spec:
  rules:
  - name: validate-readOnlyRootFilesystem
    match:
      any:
      - resources: {kinds: [Pod]}
    validate:
      message: "Root filesystem must be read-only."
      pattern:
        spec:
          containers:
          - securityContext:
              readOnlyRootFilesystem: true
```

```yaml
# 출력
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-ro-rootfs-cedde0
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ['']
      apiVersions: [v1]
      operations: [CREATE, UPDATE]
      resources: [pods]
  validations:
  - expression: (has(object.spec) && ((has(object.spec.containers) &&
      (object.spec.containers.all(__x, (has(__x.securityContext) &&
      ((has(__x.securityContext.readOnlyRootFilesystem) &&
      (__x.securityContext.readOnlyRootFilesystem == true)))))))))
    message: Root filesystem must be read-only.
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-ro-rootfs-cedde0-b
spec:
  policyName: require-ro-rootfs-cedde0
  validationActions: [Deny]
```

더 많은 예시는 [`examples/`](examples/)에 있습니다.

## Kyverno 정책 라이브러리 적용 결과

[kyverno/policies](https://github.com/kyverno/policies) `ef9843f` 커밋 기준으로 실행했습니다.

"네이티브 표현 가능"의 분류가 1차 실행 이후 수정되어 **수치를 두 가지로 적습니다.
뒤의 것이 현재 기준입니다.**

**1차 측정 당시 — 523개**

```
변환 성공    400
미지원       123
```

그 실행의 산출물이 [`converted/`](converted/)에 있습니다(401개 — 변환기 산출 400개와
이전 실험에서 남은 수작업 정책 1개). 변환된 각 정책을 원본 Kyverno 정책과 같은 클러스터에
올리고 동일한 업스트림 테스트 입력을 주어 비교했습니다.
**직접 비교가 가능했던 경우 167건이 일치했고 불일치는 0건이었습니다.**

**수정된 분류 기준 재집계 — 541개**

```
변환 성공    407
미지원       134
```

모집단이 −4 +21 +1로 바뀌었습니다.

| 변화 | 이유 |
|---|---|
| **−4** | "네이티브 표현 가능"에서 **빠진** 것. 3건은 `N-PARTIAL-TIME`(CEL에 시계가 없어 시간 조건은 CREATE에서만 재현됨), 1건은 `K-ONLY`(`validate.manifests`는 cosign 서명을 검증하는데 CEL에 암호 연산이 없음). 4건 모두 원래 미지원이라 `변환 성공`은 그대로입니다. |
| **+21** | 최종 분류에는 있는데 1차 실행에서 변환기를 돌리지 않은 것. 5건 변환, 16건 미변환. |
| **+1** | `inject-coco-initdata`. 클러스터 실측 후 `W-DYNAMIC` → `N-PARAM`으로 재분류. 변환됨. |

집계 기준: 407에는 수작업 정책 1건이 포함됩니다. 변환기 산출물만 세면 406 변환 / 135 미지원입니다.

407에 대한 주의: **그중 6건은 변환은 되지만 API 서버가 거부합니다.** 원본이 Kyverno 전용 CEL
확장(`resource.Get`, `resource.Post`)을 쓰는데 그것이 그대로 복사되기 때문입니다. 이 6건은
`converted/`에 없습니다(그 디렉터리는 523개 기준 1차 실행 결과입니다).

### 아직 변환하지 못하는 것

134건을 사유별로 나누면 다음과 같습니다.

| 사유 | 건수 |
|---|---:|
| `rule.context` → `paramRef` 매핑 | 25 |
| 지원 범위를 넘는 복잡한 JMESPath / `deny.conditions` | 48 |
| `foreach` (반복 검사) | 31 |
| 매치 범위: 리소스 이름, kind/필드 단위 `exclude`, 와일드카드 kind | 10 |
| `patchStrategicMerge` 리스트 병합 | 9 |
| `patchesJson6902` | 5 |
| `validate.podSecurity`, `validate.manifests` | 4 |
| 앵커: PSM 맵 앵커, 글로벌 `<(key)` | 2 |

`rule.context` 항목이 11에서 25로 늘어난 것은, 새로 포함된 21건 중 15건이 어드미션 시점에
ConfigMap을 읽거나 API를 호출하기(`context.apiCall`) 때문입니다. 이 부류는 VAP의
`namespaceObject` / `authorizer` / `paramRef`로 옮겨야 하는데 이 변환기에는 그 매핑이 없습니다.
따라서 CEL의 한계가 아니라 여전히 프런트엔드의 미구현 부분입니다.

이들은 CEL의 한계가 아니라 컴파일러 프런트엔드의 미구현 부분입니다. 후속 연구에서 각 유형의
대표를 손으로 변환해 클러스터에서 확인한 결과, 대표 14건 중 7건은 의미 손실 없이 변환되었고
6건은 특정 손실을 동반했으며, 1건만 원리적으로 불가능했습니다 — cosign 서명을 검증하는
`validate.manifests`로, CEL에 암호 연산 프리미티브가 없기 때문입니다.

## 알려진 한계

- **`foreach` 미지원** (31건). 가장 많은 사유는 JMESPath 지원 범위(48건)입니다.
  `jmes_to_cel`이 괄호가 들어간 식을 전부 거부하기 때문에 JMESPath 함수 호출과 필터가
  모두 탈락합니다.
- Kyverno 엔진이 제공하는 부가 기능은 CEL에 대응물이 없어 근사하거나 잃습니다: OCI 이미지
  레퍼런스 파서(`images` 변수), JSON 인코딩·디코딩, JSON6902 `/-` append(SSA 키 병합과 의미가
  다름), 내장 Pod Security Standards 엔진의 `version: latest` 추종.
- `background: true`(기존 자원에 대한 Kyverno 배경 스캔)는 네이티브에 대응 개념이 없습니다.
  VAP/MAP은 어드미션 시점 전용입니다. 다만 `validationFailureAction: Audit`은
  `validationActions: ["Audit", "Warn"]`으로 표현됩니다.
- CEL에는 현재 시각이 없습니다. 시간창 정책은 CREATE에서
  `timestamp(object.metadata.creationTimestamp)`로 재현되지만 UPDATE에서는 불가능합니다.
- 생성되는 정책 이름은 `<이름>-<16진수 6자리>` 형식입니다. 같은 입력에 대해 안정적이지만,
  기존에 쓰시던 이름과는 일치하지 않습니다.
- **적용 전에 출력을 검토하십시오.** 이 도구는 번역기이지 검증기가 아닙니다.

## 저장소 구성

```
kyverno2native.py       CLI
convert/                두 변환기 + 파드 컨트롤러 확장
classify/               네이티브 표현 가능 여부를 판정하는 구조 분류기
verify/                 변환본을 원본과 비교하는 검증 하네스
converted/              Kyverno 라이브러리 전체의 변환 결과
results/                분류, autogen 측정, 산출 출처, 검증 결과 CSV
examples/               변환 전후 대조 예시
```

## 라이선스

Apache-2.0. Kyverno 정책 라이브러리에 대한 출처 표기는 [LICENSE](LICENSE)와
[NOTICE](NOTICE)를 참고하십시오.
