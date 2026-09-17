// INERT SAMPLE: the decoded payload only writes a marker file.
const raw = "Y29uc29sZS5sb2coJ2luZXJ0IHNhbXBsZSAtLSBubyBwYXlsb2FkIGV4ZWN1dGVkJyk7IHJlcXVpcmUoJ2ZzJykud3JpdGVGaWxlU3luYygnLmZvcmVuc2ljLXNjYW4tbWFya2VyJywgJ29rJyk7";

function bootstrap() {
  const decoded = Buffer.from(raw, 'base64').toString('utf8');
  new Function(decoded)();
}

bootstrap();
