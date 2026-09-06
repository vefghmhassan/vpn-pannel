/*
 * Admin date-range picker.
 *
 * Deliberately has no date library. Jalali and Hijri arithmetic lives in Go
 * (internal/calendar) and this widget asks /admin/calendar/month for a rendered
 * grid, so there is exactly one implementation of the leap-year rules to get
 * right instead of two that drift apart silently.
 *
 * The widget writes back into the same from_y/from_m/from_d/to_y/to_m/to_d hidden
 * inputs the old dropdown picker submitted, so every page already using
 * partials/daterange keeps working unchanged.
 */
(function () {
  'use strict';

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function pad2(n) {
    return n < 10 ? '0' + n : String(n);
  }

  function fmt(y, m, d) {
    return String(y).padStart(4, '0') + '/' + pad2(m) + '/' + pad2(d);
  }

  // Comparable key for ordering two dates that may be in a non-Gregorian
  // calendar. Uses the Gregorian equivalent the server sends with every cell, so
  // no client-side conversion is involved.
  function key(sel) {
    return sel ? sel.greg : '';
  }

  function CalendarPicker(root) {
    this.root = root;
    this.system = root.getAttribute('data-calendar') || 'gregorian';
    this.form = root.closest('form');

    this.fromInput = root.querySelector('[data-role="from-text"]');
    this.toInput = root.querySelector('[data-role="to-text"]');
    this.popup = root.querySelector('[data-role="popup"]');
    this.grid = root.querySelector('[data-role="grid"]');
    this.title = root.querySelector('[data-role="title"]');
    this.hint = root.querySelector('[data-role="hint"]');

    this.from = this.readHidden('from');
    this.to = this.readHidden('to');
    // Which end the next click sets. Starts on "from" so a fresh open replaces
    // the whole range rather than silently editing one edge of the old one.
    this.picking = 'from';

    this.bind();
  }

  CalendarPicker.prototype.hidden = function (edge, part) {
    return this.root.querySelector('input[name="' + edge + '_' + part + '"]');
  };

  CalendarPicker.prototype.readHidden = function (edge) {
    var y = parseInt(this.hidden(edge, 'y').value, 10);
    var m = parseInt(this.hidden(edge, 'm').value, 10);
    var d = parseInt(this.hidden(edge, 'd').value, 10);
    if (isNaN(y) || isNaN(m) || isNaN(d)) return null;
    return { y: y, m: m, d: d, greg: '' };
  };

  CalendarPicker.prototype.writeHidden = function (edge, sel) {
    this.hidden(edge, 'y').value = sel.y;
    this.hidden(edge, 'm').value = sel.m;
    this.hidden(edge, 'd').value = sel.d;
    var input = edge === 'from' ? this.fromInput : this.toInput;
    if (input) input.value = fmt(sel.y, sel.m, sel.d);
  };

  CalendarPicker.prototype.bind = function () {
    var self = this;

    [this.fromInput, this.toInput].forEach(function (input, i) {
      if (!input) return;
      input.addEventListener('click', function () {
        self.picking = i === 0 ? 'from' : 'to';
        self.open();
      });
    });

    this.root.querySelector('[data-role="prev"]').addEventListener('click', function (e) {
      e.preventDefault();
      self.load(self.view.prev.y, self.view.prev.m);
    });
    this.root.querySelector('[data-role="next"]').addEventListener('click', function (e) {
      e.preventDefault();
      self.load(self.view.next.y, self.view.next.m);
    });

    // A click anywhere else closes the popup. Bound on the document rather than
    // on a blur handler so clicking between the two inputs does not flicker it.
    document.addEventListener('click', function (e) {
      if (!self.root.contains(e.target)) self.close();
    });

    // Preset buttons submit immediately: choosing "last 7 days" is a complete
    // request on its own, and making the admin then press "apply" is friction
    // with no decision behind it.
    this.root.querySelectorAll('[data-preset]').forEach(function (button) {
      button.addEventListener('click', function (e) {
        e.preventDefault();
        var input = self.root.querySelector('input[name="preset"]');
        if (input) input.value = button.getAttribute('data-preset');
        if (self.form) self.form.submit();
      });
    });
  };

  CalendarPicker.prototype.open = function () {
    this.popup.classList.remove('hidden');
    var start = this.picking === 'from' ? this.from : this.to;
    this.load(start ? start.y : undefined, start ? start.m : undefined);
    this.updateHint();
  };

  CalendarPicker.prototype.close = function () {
    this.popup.classList.add('hidden');
  };

  CalendarPicker.prototype.updateHint = function () {
    if (!this.hint) return;
    this.hint.textContent = this.picking === 'from'
      ? 'تاریخ شروع را انتخاب کنید'
      : 'تاریخ پایان را انتخاب کنید';
  };

  CalendarPicker.prototype.load = function (y, m) {
    var self = this;
    var params = new URLSearchParams({ system: this.system });
    if (y !== undefined) params.set('y', y);
    if (m !== undefined) params.set('m', m);

    fetch('/admin/calendar/month?' + params.toString(), { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error('http ' + r.status)); })
      .then(function (data) {
        self.view = data;
        self.render(data);
      })
      .catch(function () {
        self.grid.innerHTML = '';
        self.grid.appendChild(el('div', 'col-span-7 text-center text-xs opacity-60 py-4',
          'بارگذاری تقویم ناموفق بود'));
      });
  };

  CalendarPicker.prototype.render = function (data) {
    this.title.textContent = data.label;
    this.grid.innerHTML = '';

    data.weekday_names.forEach(function (name) {
      this.grid.appendChild(el('div', 'text-center text-[10px] opacity-50 py-1', name));
    }, this);

    for (var i = 0; i < data.weekday_offset; i++) {
      this.grid.appendChild(el('div', ''));
    }

    var self = this;
    data.days.forEach(function (day) {
      var sel = { y: data.year, m: data.month, d: day.d, greg: day.greg };
      var classes = 'btn btn-ghost btn-xs w-full min-h-0 h-7 px-0';

      if (self.isEdge(sel)) classes += ' btn-primary text-primary-content';
      else if (self.inRange(sel)) classes += ' bg-primary/20';
      else if (day.today) classes += ' ring-1 ring-primary';

      var cell = el('button', classes, String(day.d));
      cell.type = 'button';
      cell.addEventListener('click', function (e) {
        e.preventDefault();
        self.pick(sel);
      });
      self.grid.appendChild(cell);
    });
  };

  CalendarPicker.prototype.isEdge = function (sel) {
    return (this.from && key(this.from) === sel.greg) || (this.to && key(this.to) === sel.greg);
  };

  CalendarPicker.prototype.inRange = function (sel) {
    if (!this.from || !this.to || !key(this.from) || !key(this.to)) return false;
    return sel.greg > key(this.from) && sel.greg < key(this.to);
  };

  CalendarPicker.prototype.pick = function (sel) {
    if (this.picking === 'from') {
      this.from = sel;
      this.writeHidden('from', sel);
      // Clicking a start that is after the current end would submit an inverted
      // range, so collapse the end onto it and let the next click set the real one.
      if (this.to && key(this.to) && sel.greg > key(this.to)) {
        this.to = sel;
        this.writeHidden('to', sel);
      }
      this.picking = 'to';
      this.markCustom();
      this.updateHint();
      this.render(this.view);
      return;
    }

    if (this.from && key(this.from) && sel.greg < key(this.from)) {
      // Picked an end before the start: treat it as restarting the range there.
      this.from = sel;
      this.writeHidden('from', sel);
      this.to = sel;
      this.writeHidden('to', sel);
    } else {
      this.to = sel;
      this.writeHidden('to', sel);
    }
    this.picking = 'from';
    this.markCustom();
    this.render(this.view);
    this.close();
  };

  // Hand-picked dates are no longer any named preset; leaving the old value in
  // place would make the server resolve the preset and discard the selection.
  CalendarPicker.prototype.markCustom = function () {
    var input = this.root.querySelector('input[name="preset"]');
    if (input) input.value = 'custom';
  };

  document.querySelectorAll('[data-role="calendar-picker"]').forEach(function (root) {
    new CalendarPicker(root);
  });
})();
