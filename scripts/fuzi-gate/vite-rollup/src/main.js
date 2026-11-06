import {add} from './add.js';

const el = document.getElementById('app');
el.textContent = `2 + 3 = ${add(2, 3)}`;
