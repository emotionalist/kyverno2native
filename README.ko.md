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
| `X(key)` | 없어야 함 |
| `(key)` | 조건부 앵커 → `.filter()` 술어 또는 함의 |
| `+(key)` | 없을 때만 추가, **키별로** |
| `^(key)` | 리스트 원소 중 하나 이상 만족 |
| `<(key)` | 글로벌 앵커 → `matchConditions`로 올림 |
| 와일드카드 맵 키 | 존재 검사(`.exists()`). `.all()`은 매치가 없을 때 공허참이 되어 통과시킴 |
| 패턴 아래의 리스트 | 리스트 전체에 `.all()` |
| `deny.conditions` | 부정해서 `validations` 식으로. deny는 존재 한정, validations는 전칭 |
| `patchStrategicMerge`, 키 있는 리스트 | `ApplyConfiguration` |
| `patchStrategicMerge`, atomic 리스트 | `JSONPatch` — ApplyConfiguration은 atomic 리스트를 건드릴 수 없음 |

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

[kyverno/policies](https://github.com/kyverno/policies) `ef9843f` 커밋 기준, 네이티브 표현
가능으로 분류한 523개를 대상으로 실행했습니다.

```
변환 성공    400
미지원       123
```

전체 코퍼스의 변환 결과는 [`converted/`](converted/)에 있습니다(401개 — 변환기 산출 400개와
이전 실험에서 남은 수작업 정책 1개).

변환된 각 정책을 원본 Kyverno 정책과 같은 클러스터에 올리고 동일한 업스트림 테스트 입력을
주어 비교했습니다. **직접 비교가 가능했던 경우 167건이 일치했고 불일치는 0건이었습니다.**

### 아직 변환하지 못하는 것

| 사유 | 건수 |
|---|---:|
| `foreach` (반복 검사) | 30 |
| 지원 범위를 넘는 복잡한 JMESPath / `deny.conditions` | 50 |
| `patchStrategicMerge` 리스트 병합 | 9 |
| 매치 범위: 리소스 이름, kind/필드 단위 `exclude`, 와일드카드 kind | 10 |
| `patchesJson6902` | 5 |
| `rule.context` → `paramRef` 매핑 | 11 |
| 앵커: PSM 맵 앵커, 글로벌 `<(key)` | 2 |
| `validate.podSecurity`, `validate.manifests` | 5 |

이들은 CEL의 한계가 아니라 컴파일러 프런트엔드의 미구현 부분입니다. 후속 연구에서 각 유형의
대표를 손으로 변환해 클러스터에서 확인한 결과, 대표 14건 중 7건은 의미 손실 없이 변환되었고
6건은 특정 손실을 동반했으며, 1건만 원리적으로 불가능했습니다 — cosign 서명을 검증하는
`validate.manifests`로, CEL에 암호 연산 프리미티브가 없기 때문입니다.

## 알려진 한계

- **`foreach` 미지원** — 가장 큰 공백입니다.
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
