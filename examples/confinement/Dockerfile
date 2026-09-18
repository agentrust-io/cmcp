FROM python:3.12-slim@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b
RUN mkdir /export && chmod 0777 /export
COPY agent.py /agent.py
USER 10001:10001
ENTRYPOINT ["python", "-I", "/agent.py"]
