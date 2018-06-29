ARG BASE_IMAGE=ubuntu

FROM ${BASE_IMAGE}

LABEL "base image"

RUN mkdir /test-dir

WORKDIR /test-dir

RUN echo "file1/base" > file1.txt

ADD file2.txt /test-dir/

CMD for f in /test-dir/file1.txt /test-dir/file2.txt; do if [ -e ${f} ]; then echo -n "file '${f}' exists with content '$(cat ${f})'; "; else echo -n "file '${f}' does not exist; "; fi; done; echo ""
