FROM ubuntu:latest
ENV DB_PASSWORD=changeme123
ADD https://example.com/tool.sh /tool.sh
RUN curl -fsSL https://get.example.com/install | bash
CMD ["/tool.sh"]
