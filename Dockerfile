FROM debian:stable-slim
# COPY source destination
COPY chirpy /bin/chirpy
CMD ["/bin/chirpy"]
