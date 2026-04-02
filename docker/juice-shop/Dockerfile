# OWASP Juice Shop — Angular useHash: false (# 없는 Path URL)
# 공식 이미지는 이미 빌드된 프론트라 해시 라우팅만 소스에서 끌 수 있음 → 지정 태그 클론 후 한 줄 수정·재빌드.
# 빌드: docker compose build juice-shop  (최초 15~30분 가량, 네트워크 필요)
#
# node / distroless 버전은 공식 Dockerfile 과 맞춤: https://github.com/juice-shop/juice-shop/blob/master/Dockerfile

FROM node:24 AS installer
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG JUICE_SHOP_REF=v19.2.1
WORKDIR /juice-shop
RUN git clone --depth 1 --branch "${JUICE_SHOP_REF}" https://github.com/juice-shop/juice-shop.git . \
    && sed -i 's/RouterModule\.forRoot(routes, { useHash: true })/RouterModule.forRoot(routes, { useHash: false })/' frontend/src/app/app.routing.ts

RUN npm i -g typescript ts-node
RUN npm install --omit=dev --unsafe-perm
RUN npm dedupe --omit=dev
RUN rm -rf frontend/node_modules
RUN rm -rf frontend/.angular
RUN rm -rf frontend/src/assets
RUN mkdir logs
RUN chown -R 65532 logs
RUN chgrp -R 0 ftp/ frontend/dist/ logs/ data/ i18n/
RUN chmod -R g=u ftp/ frontend/dist/ logs/ data/ i18n/
RUN rm data/chatbot/botDefaultTrainingData.json || true
RUN rm ftp/legal.md || true
RUN rm i18n/*.json || true

ARG CYCLONEDX_NPM_VERSION='^2.0.0||^3.0.0||^4.0.0'
RUN npm install -g @cyclonedx/cyclonedx-npm@$CYCLONEDX_NPM_VERSION
RUN npm run sbom

FROM gcr.io/distroless/nodejs24-debian13
WORKDIR /juice-shop
COPY --from=installer --chown=65532:0 /juice-shop .
USER 65532
EXPOSE 3000
CMD ["/juice-shop/build/app.js"]
