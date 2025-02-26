FROM node:18

WORKDIR /app

ENV DATABASE_HOST=mysql

COPY package*.json .

RUN npm install

COPY . .

ARG PORT
EXPOSE ${PORT}
CMD [ "npm", "start" ]
