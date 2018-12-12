package com.example.androidthings.gattserver;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

import java.nio.ByteBuffer;
import java.util.ArrayList;

public class ConnectedHubAdapter extends ArrayAdapter<ConnectedHub> {
    private final Context context;
    private final ArrayList<ConnectedHub> elements;

    public ConnectedHubAdapter(Context context, ArrayList<ConnectedHub> elements){
        super(context, R.layout.auth_users, elements);
        this.context = context;
        this.elements = elements;
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        LayoutInflater inflater = (LayoutInflater) context.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
        View rowView = inflater.inflate(R.layout.auth_users, parent, false);
        TextView text = rowView.findViewById(R.id.users);
        if(elements.get(position).getHub() != null && elements.get(position).getMessage() != null) {
            text.setText("Cliente: " + elements.get(position).getHub().getName() + " \nMensagem enviada: " + elements.get(position).getMessage());
        }
        return rowView;
    }

}
