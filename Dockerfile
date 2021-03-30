FROM       golang:1.15.6
ADD        . /go/src/github.com/proofpoint/certificate-init-container
RUN        go install github.com/proofpoint/certificate-init-container && \
           go test github.com/proofpoint/certificate-init-container/...

FROM gcr.io/distroless/base-debian10

COPY --from=0 /go/bin/certificate-init-container /
ENTRYPOINT ["/certificate-init-container"]
