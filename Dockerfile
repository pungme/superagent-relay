FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts && cp -r node_modules /prod_modules && npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=8787
COPY --from=build /prod_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
EXPOSE 8787
USER node
CMD ["node", "dist/node.js"]
