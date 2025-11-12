const express = require('express');
const cors = require('cors');
require('dotenv').config();
const app = express();
const i18n = require('i18next');
const i18nextMiddleware = require('i18next-http-middleware');
const {english,french}=require("./lib/i18n");

// Middleware
app.use(cors("*"));


i18n.use(i18nextMiddleware.LanguageDetector);

const i18nConfig={
  fallbackLng:'en',
  interpolation:{
         escapeValue:false
  },
  resources:{
      en:english,
      fr:french
  }

}

i18n.init(i18nConfig);

app.use(i18nextMiddleware.handle(i18n));


app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the KIN Backend API' });

});


// Import and use routes
const authRoutes = require('./routes/auth');
const paymentRoutes = require('./routes/payments');



// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

const PORT = process.env.PORT || 9876;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 