{{- define "sample-ehr.labels" -}}
app.kubernetes.io/part-of: sample-ehr
app.kubernetes.io/managed-by: {{ .Release.Service }}
data-classification: phi
audit.phi-guard.io/log: enabled
{{- end -}}
