FROM alpine
ADD certificate-init-container /certificate-init-container
ENTRYPOINT ["/certificate-init-container"]
