#ifndef SONARWIDGET_H
#define SONARWIDGET_H

#include <QWidget>
#include <QPainter>
#include <cmath>

class SonarWidget : public QWidget {
public:
    explicit SonarWidget(QWidget *parent = nullptr)
        : QWidget(parent) {
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }
protected:
    void paintEvent(QPaintEvent*) override {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor("#2a2a35"));

        int w = width(), h = height();
        int cx = w/2, cy = h/2;
        int maxR = qMin(w,h)/2 - 10;

        QPen pen(QColor("#4f6e5c"), 2);
        p.setPen(pen);
        // concentryczne okręgi
        for (int r = maxR/4; r <= maxR; r += maxR/4)
            p.drawEllipse(QPoint(cx,cy), r, r);
        // osie
        for (int i = 0; i < 4; ++i) {
            double ang = M_PI/2 * i;
            p.drawLine(cx, cy,
                       cx + maxR * std::cos(ang),
                       cy - maxR * std::sin(ang));
        }
        // przykładowe punkty
        p.setBrush(QColor("#8fc1a0"));
        QVector<QPoint> pts {
            {cx + maxR/2, cy},
            {cx - maxR/3, cy - maxR/4},
            {cx + maxR/5, cy + maxR/3}
        };
        for (auto &pt : pts)
            p.drawEllipse(pt, 6, 6);
    }
};

#endif // SONARWIDGET_H
